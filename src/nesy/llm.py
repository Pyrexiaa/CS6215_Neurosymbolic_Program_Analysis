"""LLM access for the neural stages (N1-N3).

* ``OpenAICompatClient`` talks to SoCLaaS (or any OpenAI-compatible endpoint).
* ``MockLLM`` returns scripted answers; the test-suite and dry runs use it.
* Every call is cached on disk (keyed by model, messages, temperature and sample index)
  so experiments can be re-run offline and repeated runs cost no tokens.
* Every call is appended to a JSONL ledger (stage, tokens, latency) for the cost tables.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

Message = Dict[str, str]


@dataclass
class LLMResponse:
    text: str
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_s: float = 0.0
    cached: bool = False
    raw: Dict[str, Any] = field(default_factory=dict)
    finish_reason: str = ""      # "length" = answer cut off by max_tokens


class LLMError(RuntimeError):
    pass


class BaseLLM:
    model: str = "unknown"

    def __init__(self, cache_dir: Optional[Path] = None, ledger: Optional[Path] = None):
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.ledger = Path(ledger) if ledger else None
        self.context: Dict[str, Any] = {}   # merged into every ledger row (subject, config, run)
        self.usage: Dict[str, Dict[str, float]] = {}   # stage -> counters (in-memory, per process)
        self.served_models: set = set()   # model ids reported by the server (e.g. what "default" maps to)

    # -- to implement
    def _complete(self, messages: List[Message], temperature: float, max_tokens: int, seed: Optional[int]) -> LLMResponse:
        raise NotImplementedError

    # -- public API
    def chat(self, messages: List[Message], stage: str, temperature: float = 0.0, max_tokens: int = 4096,
             sample: int = 0, use_cache: bool = True) -> LLMResponse:
        key = self._cache_key(messages, temperature, max_tokens, sample)
        if use_cache and self.cache_dir:
            hit = self._cache_get(key)
            if hit is None:
                hit = self._legacy_cache_get(messages, temperature, max_tokens, sample)
                if hit is not None:
                    self._cache_put(key, hit)  # promote a provenance-verified legacy answer
            if hit is not None:
                hit.cached = True
                self._log(stage, hit, key)
                return hit
        seed = None if temperature == 0 else 1000 + sample
        resp = self._complete(messages, temperature, max_tokens, seed)
        if self.cache_dir:
            self._cache_put(key, resp)
        self._log(stage, resp, key)
        return resp

    def cache_identity(self) -> dict:
        """Inputs not already represented by the rendered messages and sampling settings.

        Only a hash of the endpoint is exposed; API credentials never enter cache metadata.
        Non-transport clients retain the historical keys used by fixture/offline readers.
        """
        identity = {"model": self.model}
        endpoint = getattr(self, "base_url", None)
        if endpoint is not None:
            identity["endpoint_sha256"] = hashlib.sha256(str(endpoint).rstrip("/").encode()).hexdigest()
            identity["extra_body"] = getattr(self, "extra_body", {}) or {}
        return identity

    def _cache_key(self, messages, temperature, max_tokens, sample) -> str:
        identity = self.cache_identity()
        if "endpoint_sha256" not in identity:
            return self._legacy_cache_key(messages, temperature, max_tokens, sample)
        blob = json.dumps({"version": 2, "identity": identity, "msgs": messages,
                           "t": temperature, "mt": max_tokens, "s": sample}, sort_keys=True)
        return hashlib.sha256(blob.encode()).hexdigest()

    def allow_legacy_cache(self, served_models: List[str], provenance: str) -> None:
        """Bind old answers to a caller-verified endpoint/configuration for safe migration.

        Call only after independently checking the historical experiment provenance.
        An identity mismatch never falls back to legacy responses. Aliases such as
        'default' additionally require the historical served-model allowlist.
        """
        if not self.cache_dir or not provenance.strip() or not served_models:
            raise ValueError("legacy migration needs a cache directory, served models and provenance")
        path = self.cache_dir / "legacy-identities.json"
        data = json.loads(path.read_text()) if path.exists() else {"version": 1, "identities": []}
        item = {"identity": self.cache_identity(), "served_models": sorted(set(served_models)),
                "provenance": provenance}
        data["identities"] = [x for x in data["identities"] if x["identity"] != item["identity"]] + [item]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2))

    def _legacy_cache_get(self, messages, temperature, max_tokens, sample) -> Optional[LLMResponse]:
        path = self.cache_dir / "legacy-identities.json"
        if not path.exists():
            return None
        try:
            registrations = json.loads(path.read_text())["identities"]
            registration = next((x for x in registrations if x["identity"] == self.cache_identity()), None)
            if registration is None:
                return None
            hit = self._cache_get(self._legacy_cache_key(messages, temperature, max_tokens, sample))
            return hit if hit and hit.model in registration["served_models"] else None
        except (ValueError, KeyError, TypeError, OSError):
            return None

    def _legacy_cache_key(self, messages, temperature, max_tokens, sample) -> str:
        blob = json.dumps({"m": self.model, "msgs": messages, "t": temperature, "mt": max_tokens, "s": sample},
                          sort_keys=True)
        return hashlib.sha256(blob.encode()).hexdigest()

    def _cache_get(self, key: str) -> Optional[LLMResponse]:
        p = self.cache_dir / key[:2] / f"{key}.json"
        if p.exists():
            try:
                d = json.loads(p.read_text())
                return LLMResponse(**d)
            except Exception:
                return None
        return None

    def _cache_put(self, key: str, resp: LLMResponse) -> None:
        p = self.cache_dir / key[:2] / f"{key}.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        d = asdict(resp)
        d["cached"] = False
        p.write_text(json.dumps(d))

    def usage_snapshot(self) -> Dict[str, Dict[str, float]]:
        return {k: dict(v) for k, v in self.usage.items()}

    @staticmethod
    def usage_diff(after: Dict[str, Dict[str, float]], before: Dict[str, Dict[str, float]]) -> Dict[str, Dict[str, float]]:
        out = {}
        for stage, a in after.items():
            b = before.get(stage, {})
            d = {k: round(v - b.get(k, 0), 3) for k, v in a.items()}
            if d.get("calls"):
                out[stage] = d
        return out

    def _log(self, stage: str, resp: LLMResponse, key: str) -> None:
        u = self.usage.setdefault(stage, {"calls": 0, "cached_calls": 0, "prompt_tokens": 0, "completion_tokens": 0,
                                          "fresh_prompt_tokens": 0, "fresh_completion_tokens": 0, "latency_s": 0.0,
                                          "truncated": 0})
        u["calls"] += 1
        # Logical generation time represented by replies, including reused answers.
        # latency_s below remains time spent on fresh requests in this execution.
        u["response_latency_s"] = u.get("response_latency_s", 0.0) + resp.latency_s
        u["truncated"] = u.get("truncated", 0) + (1 if resp.finish_reason == "length" else 0)
        if resp.model:
            self.served_models.add(resp.model)
        u["prompt_tokens"] += resp.prompt_tokens
        u["completion_tokens"] += resp.completion_tokens
        if resp.cached:
            u["cached_calls"] += 1
        else:
            u["fresh_prompt_tokens"] += resp.prompt_tokens
            u["fresh_completion_tokens"] += resp.completion_tokens
            u["latency_s"] += resp.latency_s
        if not self.ledger:
            return
        self.ledger.parent.mkdir(parents=True, exist_ok=True)
        row = {"stage": stage, "model": resp.model,
               "prompt_tokens": resp.prompt_tokens, "completion_tokens": resp.completion_tokens,
               "latency_s": round(resp.latency_s, 3), "cached": resp.cached, "key": key[:16],
               "finish_reason": resp.finish_reason}
        row.update(self.context)
        with open(self.ledger, "a") as f:
            f.write(json.dumps(row) + "\n")


class OpenAICompatClient(BaseLLM):
    def __init__(self, base_url: str, api_key: str, model: str, timeout_s: float = 300, max_retries: int = 4,
                 cache_dir: Optional[Path] = None, ledger: Optional[Path] = None, extra_body: Optional[dict] = None):
        super().__init__(cache_dir, ledger)
        self.base_url = base_url
        self.api_key = api_key
        self.model = model
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        self.extra_body = extra_body or {}
        self._client = None

    def _sdk(self):
        if self._client is None:
            try:
                from openai import OpenAI
            except ImportError as e:  # pragma: no cover
                raise LLMError("The 'openai' package is required: pip install -r requirements.txt") from e
            self._client = OpenAI(base_url=self.base_url, api_key=self.api_key, timeout=self.timeout_s,
                                  max_retries=0)
        return self._client

    def list_models(self) -> List[str]:
        return [m.id for m in self._sdk().models.list().data]

    def _complete(self, messages, temperature, max_tokens, seed) -> LLMResponse:
        last_err: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            t0 = time.time()
            try:
                kwargs = dict(model=self.model, messages=messages, temperature=temperature, max_tokens=max_tokens)
                if seed is not None:
                    kwargs["seed"] = seed
                if self.extra_body:
                    kwargs["extra_body"] = self.extra_body
                r = self._sdk().chat.completions.create(**kwargs)
                text = r.choices[0].message.content or ""
                finish = getattr(r.choices[0], "finish_reason", "") or ""
                usage = getattr(r, "usage", None)
                return LLMResponse(text=text, model=getattr(r, "model", self.model) or self.model,
                                   prompt_tokens=getattr(usage, "prompt_tokens", 0) or 0,
                                   completion_tokens=getattr(usage, "completion_tokens", 0) or 0,
                                   latency_s=time.time() - t0, finish_reason=str(finish))
            except Exception as e:  # network errors, 429, 5xx
                last_err = e
                time.sleep(min(60, 2 ** attempt * 3))
        raise LLMError(f"LLM call failed after {self.max_retries + 1} attempts: {last_err}")


Responder = Callable[[List[Message], str], str]


class MockLLM(BaseLLM):
    """Deterministic stand-in. ``responder(messages, stage) -> text``."""

    model = "mock"

    def __init__(self, responder: Responder, cache_dir: Optional[Path] = None, ledger: Optional[Path] = None):
        super().__init__(cache_dir, ledger)
        self.responder = responder
        self.calls: List[Dict[str, Any]] = []
        self._stage = ""

    def chat(self, messages, stage, temperature=0.0, max_tokens=4096, sample=0, use_cache=True):
        self._stage = stage
        self.calls.append({"stage": stage, "messages": messages, "sample": sample, "temperature": temperature})
        return super().chat(messages, stage, temperature, max_tokens, sample, use_cache)

    def _complete(self, messages, temperature, max_tokens, seed):
        text = self.responder(messages, self._stage)
        n_in = sum(len(m["content"]) for m in messages) // 4
        return LLMResponse(text=text, model=self.model, prompt_tokens=n_in, completion_tokens=len(text) // 4)


# ----------------------------------------------------------------- parsing helpers

_THINK = re.compile(r"<think>.*?</think>", re.S)


def strip_reasoning(text: str) -> str:
    """Remove ``<think>`` blocks that reasoning models (e.g. Qwen3) prepend."""
    return _THINK.sub("", text or "").strip()


def extract_code_block(text: str, lang: str = "java") -> Optional[str]:
    text = strip_reasoning(text)
    m = re.search(rf"```{lang}\s*\n(.*?)```", text, re.S | re.I)
    if m:
        return m.group(1).strip()
    m = re.search(r"```\s*\n(.*?)```", text, re.S)
    return m.group(1).strip() if m else None


def extract_json(text: str) -> Any:
    """Return the first JSON value found in a model answer (fenced or bare)."""
    text = strip_reasoning(text)
    for m in re.finditer(r"```(?:json)?\s*\n(.*?)```", text, re.S | re.I):
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            continue
    # bare: scan for a balanced {...} or [...]
    for start, ch in enumerate(text):
        if ch not in "{[":
            continue
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            c = text[i]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
                continue
            if c == '"':
                in_str = True
            elif c in "{[":
                depth += 1
            elif c in "}]":
                depth -= 1
                if depth == 0:
                    cand = text[start:i + 1]
                    try:
                        return json.loads(cand)
                    except json.JSONDecodeError:
                        break
        # try next opening bracket
    raise ValueError("no JSON value found in model output")


def load_env_file(path: Path) -> Dict[str, str]:
    """Minimal .env reader (KEY=VALUE lines, # comments). Does not override os.environ."""
    out: Dict[str, str] = {}
    p = Path(path)
    if not p.exists():
        return out
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip().strip('"').strip("'")
        out[k.strip()] = v
    return out


def client_from_env(env: Dict[str, str], cache_dir: Optional[Path], ledger: Optional[Path],
                    model: Optional[str] = None, timeout_s: float = 300, extra_body: Optional[dict] = None
                    ) -> OpenAICompatClient:
    def get(k):
        return os.environ.get(k) or env.get(k)
    base, key = get("SOCLAAS_BASE_URL"), get("SOCLAAS_API_KEY")
    if not base or not key:
        raise LLMError("SOCLAAS_BASE_URL / SOCLAAS_API_KEY missing: copy .env.example to .env and fill it in")
    return OpenAICompatClient(base, key, model or get("SOCLAAS_MODEL") or "default", timeout_s=timeout_s,
                              cache_dir=cache_dir, ledger=ledger, extra_body=extra_body)
