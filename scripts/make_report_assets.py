#!/usr/bin/env python3
"""Build the report's figures and tables from the study results (no LLM or Tai-e calls).

    python scripts/make_report_assets.py                 # reads results/, writes report/figures + report/tables
    python scripts/make_report_assets.py --results results --out report

Run `python -m nesy evaluate` first. Every number in the report tables comes from
results/summary/*.csv or results/runs/**/run*.json, so re-running this script after labelling
(or after new runs) updates the report. Figures are matplotlib PDFs: edit the STYLE block or the
plotting functions below to tune them.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

# ----------------------------------------------------------------------------------------- STYLE
SUBJECTS = ["zt-zip", "spark", "cron-utils", "perfecto-plugin"]
SUBJECT_LABEL = {"zt-zip": "zt-zip", "spark": "spark", "cron-utils": "cron-utils", "perfecto-plugin": "perfecto"}
MAIN = ["B1", "B2", "iris-like", "v1", "v2", "v3", "v4"]   # baselines first, then this work
ABLATIONS = ["v3-noV2", "v3-noV3", "v3-noval"]
LABEL = {"iris-like": "IRIS-style", "v3-noV2": "v3 w/o V2", "v3-noV3": "v3 w/o V3", "v3-noval": "v3 w/o V2+V3"}
GROUP_COLOR = {"baseline": "#7f7f7f", "iris": "#e08a2c", "ours": "#2b6cb0", "ablation": "#9bb7d9"}
GROUP = {"B1": "baseline", "B2": "baseline", "v1": "ours", "iris-like": "iris", "v2": "ours", "v3": "ours",
         "v4": "ours", "v3-noV2": "ablation", "v3-noV3": "ablation", "v3-noval": "ablation"}
plt.rcParams.update({
    "font.family": "serif", "font.serif": ["Linux Libertine O", "Libertinus Serif", "DejaVu Serif"],
    "font.size": 8, "axes.titlesize": 8, "axes.labelsize": 8, "legend.fontsize": 7,
    "xtick.labelsize": 7, "ytick.labelsize": 7, "axes.spines.top": False, "axes.spines.right": False,
    "pdf.fonttype": 42, "savefig.bbox": "tight", "savefig.pad_inches": 0.02,
})
COLUMN_W = 3.33   # inches, one ACM sigconf column


def lab(c: str) -> str:
    return LABEL.get(c, c)


# ------------------------------------------------------------------------------------------ data
def read_csv(p: Path) -> list:
    with open(p, newline="") as f:
        return list(csv.DictReader(f))


def num(x, default=None):
    try:
        return float(x)
    except (TypeError, ValueError):
        return default


def test_subject_ids() -> list:
    """Held-out test subjects (role: test in config/subjects.yaml), in file order."""
    import yaml
    data = yaml.safe_load((Path(__file__).resolve().parents[1] / "config" / "subjects.yaml").read_text())
    return [s["id"] for s in data.get("subjects", []) if s.get("role") == "test"]


def load_runs(results: Path, test: bool = False) -> list:
    """Development runs by default; test=True returns only the held-out test runs (never mixed)."""
    tests = set(test_subject_ids())
    out = []
    for p in sorted((results / "runs").rglob("run*.json")):
        try:
            r = json.loads(p.read_text())
        except json.JSONDecodeError:
            continue
        if (r.get("subject") in tests) == test:
            out.append(r)
    return out


def fmt(x, nd=2, pct=False, dash="--"):
    v = num(x)
    if v is None:
        return dash
    if pct:
        return f"{100 * v:.0f}\\%"
    return f"{v:.{nd}f}" if nd else f"{v:,.0f}"


# --------------------------------------------------------------------------------------- figures
def fig_detection_vs_alarms(head: dict, out: Path) -> None:
    """Mean CVE detection rate vs. alarms a user must read (buggy versions, sum over subjects)."""
    fig, ax = plt.subplots(figsize=(COLUMN_W, 2.05))
    offsets = {"B1": (6, -3), "B2": (-14, -11), "v1": (5, 3), "iris-like": (5, -9), "v2": (5, -4), "v3": (5, -3),
               "v4": (-4, 6)}
    for c in MAIN:
        h = head.get(c)
        if not h:
            continue
        x, y = num(h["alarms_buggy_total"]), num(h["detection_rate_mean"])
        ax.scatter([x], [y], s=34, color=GROUP_COLOR[GROUP[c]], zorder=3, edgecolor="white", linewidth=0.6)
        dx, dy = offsets.get(c, (5, 3))
        ax.annotate(f"{lab(c)} ({int(num(h['cves_detected']))}/4)", (x, y), textcoords="offset points",
                    xytext=(dx, dy), fontsize=6.8, ha="left" if dx >= 0 else "right")
    ax.set_xscale("log")
    ax.set_xlim(150, 4000)
    ax.set_xticks([200, 500, 1000, 2000])
    ax.set_xticklabels(["200", "500", "1,000", "2,000"])
    ax.minorticks_off()
    ax.set_ylim(0, 1.08)
    ax.set_xlabel("alarms on the buggy versions (log scale)")
    ax.set_ylabel("mean CVE detection rate")
    ax.grid(True, which="major", color="#e6e6e6", linewidth=0.5, zorder=0)
    ax.legend(handles=[Patch(color=GROUP_COLOR[g], label=t) for g, t in
                       (("baseline", "symbolic baseline"), ("iris", "IRIS-style"), ("ours", "this work"))],
              loc="lower right", frameon=False, handlelength=1.0)
    fig.savefig(out, metadata={"CreationDate": None, "ModDate": None})
    plt.close(fig)


def fig_differential(rows: list, out: Path) -> None:
    """Exact mean alarm counts; common colour scale avoids misleading panel axes."""
    import math
    import numpy as np
    from matplotlib.colors import Normalize
    cfgs = list(MAIN)
    by = {(r["subject"], r["version"], r["config"]): r for r in rows}
    matrices = []
    for subject in SUBJECTS:
        matrices.append(np.array([[num((by.get((subject, version, config)) or {}).get("reported_gt_mean"), 0)
                                   for version in ("buggy", "fixed")] for config in cfgs]))
    maximum = max(float(matrix.max()) for matrix in matrices)
    fig, axes = plt.subplots(1, 4, figsize=(COLUMN_W * 2.08, 2.02))
    norm = Normalize(vmin=0, vmax=math.log1p(maximum))
    for ax, subject, matrix in zip(axes, SUBJECTS, matrices):
        ax.imshow(np.log1p(matrix), cmap="Blues", norm=norm, aspect="auto")
        for row in range(len(cfgs)):
            for col in range(2):
                value = matrix[row, col]
                label = f"{value:.0f}" if abs(value - round(value)) < 0.005 else f"{value:.1f}"
                dark = norm(math.log1p(value)) > 0.6
                ax.text(col, row, label, ha="center", va="center", fontsize=7.5,
                        color="white" if dark else "#172b42")
        ax.set_title(SUBJECT_LABEL[subject], pad=5)
        ax.set_xticks([0, 1], ["Buggy", "Fixed"])
        ax.xaxis.tick_top()
        ax.set_yticks(range(len(cfgs)), [lab(c) for c in cfgs])
        ax.tick_params(axis="both", length=0, labelsize=6.6)
        ax.set_xticks([-.5, .5, 1.5], minor=True)
        ax.set_yticks([i-.5 for i in range(len(cfgs)+1)], minor=True)
        ax.grid(which="minor", color="white", linewidth=1)
        ax.tick_params(which="minor", length=0)
        for spine in ax.spines.values():
            spine.set_visible(False)
    fig.subplots_adjust(wspace=0.67, top=.78, bottom=.08)
    fig.text(.5, 1.01, "Patch-method-relevant alarms: mean count per run", ha="center", fontsize=8)
    fig.text(.5, -.03, "Darker cells = more alarms (shared log(1 + count) colour scale); numbers are counts, not CVEs.",
             ha="center", fontsize=6.3)
    fig.savefig(out, metadata={"CreationDate": None, "ModDate": None})
    plt.close(fig)


def fig_runs(runs: list, out: Path) -> None:
    """Per-run outcome on the buggy versions: detected / missed, plus fallbacks and Tai-e crashes."""
    cfgs = MAIN + ABLATIONS
    cells = {}
    for r in runs:
        if r["version"] != "buggy" or r["config"] not in cfgs:
            continue
        cells[(r["config"], r["subject"], r["run"])] = r
    fig, ax = plt.subplots(figsize=(COLUMN_W, 2.1))
    cols = [(s, k) for s in SUBJECTS for k in range(3)]
    for yi, c in enumerate(cfgs):
        for xi, (s, k) in enumerate(cols):
            r = cells.get((c, s, k)) or (cells.get((c, s, 0)) if c in ("B1", "B2") else None)
            if r is None:
                continue
            ok = r["taie"]["ok"]
            color = "#2b6cb0" if (ok and r["detected"]) else ("#d9d9d9" if ok else "#c0392b")
            ax.add_patch(plt.Rectangle((xi + 0.06, yi + 0.08), 0.88, 0.84, color=color, linewidth=0))
            if r["driver"]["kind"] == "llm-fallback-template":
                ax.text(xi + 0.5, yi + 0.52, "F", ha="center", va="center", fontsize=6, color="black")
    ax.set_xlim(0, len(cols))
    ax.set_ylim(len(cfgs), 0)
    ax.set_yticks([i + 0.5 for i in range(len(cfgs))])
    ax.set_yticklabels([lab(c) for c in cfgs])
    ax.set_xticks([1.5 + 3 * i for i in range(len(SUBJECTS))])
    ax.set_xticklabels([SUBJECT_LABEL[s] for s in SUBJECTS])
    for i in range(1, len(SUBJECTS)):
        ax.axvline(3 * i, color="white", linewidth=2)
    ax.tick_params(length=0)
    for sp in ax.spines.values():
        sp.set_visible(False)
    ax.legend(handles=[Patch(color="#2b6cb0", label="CVE detected"), Patch(color="#d9d9d9", label="missed"),
                       Patch(color="#c0392b", label="Tai-e crash")],
              loc="upper center", bbox_to_anchor=(0.42, -0.1), ncol=3, frameon=False, handlelength=0.9)
    fig.savefig(out, metadata={"CreationDate": None, "ModDate": None})
    plt.close(fig)


CAT_COLOR = {"TP": "#2f855a", "DRV": "#805ad5", "SPEC-FP": "#dd6b20", "IMP": "#a0aec0", "SAN": "#3182ce"}
CAT_LABEL = {"TP": "TP", "DRV": "FP: driver (DRV)", "SPEC-FP": "FP: wrong spec (SPEC-FP)",
             "IMP": "FP: imprecision (IMP)", "SAN": "FP: sanitised (SAN)"}


def fig_label_outcomes(labs: dict, out: Path) -> None:
    """Distinct labelled flows reported by each configuration, by outcome (all subjects and versions)."""
    cfgs = [c for c in MAIN if c in labs]
    fig, ax = plt.subplots(figsize=(COLUMN_W, 1.85))
    for yi, c in enumerate(cfgs):
        left = 0.0
        for k in CAT_COLOR:
            v = num(labs[c].get(k), 0)
            if v:
                ax.barh(yi, v, left=left, color=CAT_COLOR[k], height=0.7, linewidth=0)
                if v >= 25:
                    ax.text(left + v / 2, yi, f"{v:.0f}", ha="center", va="center", fontsize=5.8,
                            color="white" if k != "IMP" else "black")
            left += v
        ax.text(left + 4, yi, f"{num(labs[c].get('TP'), 0):.0f} TP", va="center", fontsize=6.2)
    ax.set_yticks(range(len(cfgs)))
    ax.set_yticklabels([lab(c) for c in cfgs])
    ax.invert_yaxis()
    ax.set_xlabel("labelled flows reported (distinct, buggy + fixed)")
    ax.grid(True, axis="x", color="#e6e6e6", linewidth=0.5)
    ax.set_axisbelow(True)
    ax.legend(handles=[Patch(color=CAT_COLOR[k], label=CAT_LABEL[k]) for k in CAT_COLOR],
              loc="upper center", bbox_to_anchor=(0.45, -0.3), ncol=3, frameon=False, handlelength=0.9,
              fontsize=6.2, columnspacing=0.8)
    fig.savefig(out, metadata={"CreationDate": None, "ModDate": None})
    plt.close(fig)


def label_totals(labels_dir: Path) -> dict:
    """Counts over the labelled rows of labels/*.csv (by outcome and by FP category)."""
    import re
    tot = defaultdict(int)
    for p in sorted(labels_dir.glob("*.csv")):
        for r in read_csv(p):
            lab_ = (r.get("label") or "").strip().upper()
            if lab_ not in ("TP", "FP"):
                continue
            tot["all"] += 1
            tot["prio"] += 1 if r.get("priority") else 0
            if lab_ == "TP":
                tot["TP"] += 1
            else:
                m = re.search(r"\b(DRV|SPEC-FP|IMP|SAN|HALLU|TOOL)\b", r.get("notes") or "")
                tot[m.group(1) if m else "?"] += 1
            tot["claude"] += 1 if "claude-labelled" in (r.get("notes") or "") else 0
    return tot


# ---------------------------------------------------------------------------------------- tables
def tab_subjects(subj: list) -> str:
    rows = [r for r in subj if r["version"] == "buggy"]
    order = {s: i for i, s in enumerate(SUBJECTS)}
    rows.sort(key=lambda r: order.get(r["subject"], 9))
    cwe = {"CWE-022": "Path trav.", "CWE-094": "Code inj.", "CWE-078": "OS cmd inj.", "CWE-079": "XSS"}
    lines = [r"\begin{tabular}{@{}llrrrrr@{}}", r"\toprule",
             r"Subject & CVE (CWE) & LoC & Jars & APIs & Fix & Tai-e (s) \\", r"\midrule"]
    for r in rows:
        lines.append(f"{SUBJECT_LABEL[r['subject']]} & {r['cve'].replace('CVE-', '')} ({cwe.get(r['cwe'], r['cwe'])}) & "
                     f"{fmt(r['non_blank_loc'], 0)} & {r['dependency_jars']} & {r['external_apis']} & "
                     f"{r['gt_methods']} & {fmt(r['b1_taie_s'], 1)} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


def tab_headline(head: dict) -> str:
    cfgs = [c for c in MAIN if c in head]   # ablations are reported in the text
    lines = [r"\begin{tabular}{@{}lrrrrrrrr@{}}", r"\toprule",
             r" & \multicolumn{4}{c}{IRIS metrics} & \multicolumn{3}{c}{LLM-judged sample} & \\",
             r"\cmidrule(lr){2-5}\cmidrule(lr){6-8}",
             r"Config & Det. & Rate & FDR & F1 & Conf. & TP & Prec. & Alarms \\", r"\midrule"]
    for c in cfgs:
        h = head[c]
        if c == "v3-noV2":
            lines.append(r"\midrule")
        conf, tpr = h.get("cves_confirmed"), h.get("cves_tp_reported")
        lines.append(f"{lab(c)} & {h['cves_detected']}/4 & {fmt(h['detection_rate_mean'], pct=True)} & "
                     f"{fmt(h['iris_avg_fdr'])} & {fmt(h['iris_avg_f1'])} & "
                     f"{(conf + '/4') if conf not in (None, '') else '--'} & "
                     f"{(tpr + '/4') if tpr not in (None, '') else '--'} & {fmt(h.get('precision_mean'))} & "
                     f"{fmt(h['alarms_buggy_total'], 0)} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


def tab_persubject(rows: list) -> str:
    by = {(r["subject"], r["version"], r["config"]): r for r in rows}
    cfgs = [c for c in MAIN if any(k[2] == c for k in by)]
    head = " & ".join(f"\\multicolumn{{2}}{{c}}{{{SUBJECT_LABEL[s]}}}" for s in SUBJECTS)
    cm = "".join(f"\\cmidrule(lr){{{2 + 2 * i}-{3 + 2 * i}}}" for i in range(len(SUBJECTS)))
    lines = [r"\begin{tabular}{@{}l" + "rr" * len(SUBJECTS) + r"@{}}", r"\toprule",
             f"Config & {head} \\\\", cm,
             " & " + " & ".join(["B", "F"] * len(SUBJECTS)) + r" \\", r"\midrule"]
    for c in cfgs:
        cells = []
        for s in SUBJECTS:
            for v in ("buggy", "fixed"):
                r = by.get((s, v, c))
                d = num(r["detected_rate"]) if r else None
                cells.append("--" if d is None else (f"{d:.2f}".rstrip("0").rstrip(".") if d not in (0.0, 1.0)
                                                     else str(int(d))))
        lines.append(f"{lab(c)} & " + " & ".join(cells) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


def tab_cost(rows: list, budget: dict, head: dict) -> str:
    """Stage effects and cost per configuration (sums/means over all subjects and versions)."""
    agg = defaultdict(lambda: defaultdict(list))
    for r in rows:
        for k in ("spec_accepted_mean", "spec_rejected_mean", "removed_by_triage_mean", "removed_gt_by_triage_mean",
                  "v3_rejected_mean", "flowset_jaccard"):
            v = num(r.get(k))
            if v is not None:
                agg[r["config"]][k].append(v)
    cfgs = [c for c in ["iris-like", "v1", "v2", "v3", "v4"] if c in budget]   # LLM configurations only
    lines = [r"\begin{tabular}{@{}lrrrrrrr@{}}", r"\toprule",
             r"Config & Spec & Rej. & Rem. & Rem.GT & V3 & Calls & Jacc. \\", r"\midrule"]
    for c in cfgs:
        a = agg[c]
        mean = (lambda k: sum(a[k]) / len(a[k]) if a[k] else None)
        tot = (lambda k: sum(a[k]) if a[k] else None)
        lines.append(f"{lab(c)} & {fmt(mean('spec_accepted_mean'), 1)} & {fmt(mean('spec_rejected_mean'), 1)} & "
                     f"{fmt(tot('removed_by_triage_mean'), 0)} & {fmt(tot('removed_gt_by_triage_mean'), 0)} & "
                     f"{fmt(tot('v3_rejected_mean'), 0)} & {fmt(budget[c]['llm_calls'], 0)} & "
                     f"{fmt(mean('flowset_jaccard'))} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


def numbers_tex(head: dict, budget: dict, runs: list, tot: dict = None, labs: dict = None) -> str:
    """\\newcommand macros for numbers quoted in the text, so the prose updates with the data."""
    def h(c, k, nd=2, pct=False):
        return fmt((head.get(c) or {}).get(k), nd, pct)
    crashes = sum(1 for r in runs if r["config"] in ("v3-noV2", "v3-noval") and not r["taie"]["ok"])
    noval_runs = sum(1 for r in runs if r["config"] in ("v3-noV2", "v3-noval"))
    fallbacks = len({(r["subject"], r["version"], r["run"], r["config"] == "v4") for r in runs
                     if r["driver"]["kind"] == "llm-fallback-template"})
    llm_runs = sum(1 for r in runs if r["config"] not in ("B1", "B2"))
    total_calls = sum(int(num(b["llm_calls"], 0)) for b in budget.values())
    flows = {(r["subject"], r["version"], f["key"]) for r in runs for f in r["flows"] if f.get("reported")}
    macros = {
        "NumRuns": str(len(runs)), "NumFlows": f"{len(flows):,}", "NumLLMRuns": str(llm_runs), "TotalCalls": f"{total_calls:,}",
        "CrashRuns": str(crashes), "NovalRuns": str(noval_runs), "FallbackDrivers": str(fallbacks),
    }
    for c, tag in (("B1", "BOne"), ("B2", "BTwo"), ("v1", "VOne"), ("iris-like", "Iris"), ("v2", "VTwo"),
                   ("v3", "VThree"), ("v4", "VFour")):
        macros[f"{tag}Det"] = h(c, "cves_detected", 0)
        macros[f"{tag}Rate"] = h(c, "detection_rate_mean", pct=True)
        macros[f"{tag}FDR"] = h(c, "iris_avg_fdr")
        macros[f"{tag}FOne"] = h(c, "iris_avg_f1")
        macros[f"{tag}Alarms"] = h(c, "alarms_buggy_total", 0)
        macros[f"{tag}AlarmsFixed"] = h(c, "alarms_fixed_total", 0)
        macros[f"{tag}Diff"] = h(c, "differential_ok", 0)
        macros[f"{tag}Conf"] = h(c, "cves_confirmed", 0)
        macros[f"{tag}Prec"] = h(c, "precision_mean")
        macros[f"{tag}TPRep"] = h(c, "cves_tp_reported", 0)
        macros[f"{tag}TPRate"] = h(c, "tp_reported_rate_mean", pct=True)
        macros[f"{tag}ConfRate"] = h(c, "confirmed_rate_mean", pct=True)
        if labs and c in labs:
            macros[f"{tag}LabTP"] = str(int(num(labs[c]["TP"], 0)))
            macros[f"{tag}Lab"] = str(int(num(labs[c]["labelled"], 0)))
            macros[f"{tag}LabIMP"] = str(int(num(labs[c]["IMP"], 0)))
            macros[f"{tag}LabSPEC"] = str(int(num(labs[c]["SPEC-FP"], 0)))
    tot = tot or {}
    for k, name in (("all", "NumLabelled"), ("TP", "NumLabTP"), ("DRV", "NumLabDRV"), ("SPEC-FP", "NumLabSPEC"),
                    ("IMP", "NumLabIMP"), ("SAN", "NumLabSAN"), ("claude", "NumLabClaude")):
        macros[name] = str(tot.get(k, 0))
    fp = sum(tot.get(k, 0) for k in ("DRV", "SPEC-FP", "IMP", "SAN", "HALLU", "TOOL", "?"))
    macros["NumLabFP"] = str(fp)
    for k, name in (("DRV", "PctLabDRV"), ("SPEC-FP", "PctLabSPEC"), ("IMP", "PctLabIMP"), ("SAN", "PctLabSAN")):
        macros[name] = f"{100 * tot.get(k, 0) / fp:.0f}\\%" if fp else "--"
    out = ["% Generated by scripts/make_report_assets.py -- do not edit by hand."]
    out += [f"\\newcommand{{\\{k}}}{{{v}}}" for k, v in sorted(macros.items())]
    return "\n".join(out) + "\n"


def tab_heldout(rows: list, head: dict) -> str:
    """Held-out test set: share of runs flagging the CVE per subject on buggy/fixed, plus alarms and F1."""
    subjects = [s for s in test_subject_ids() if any(r["subject"] == s for r in rows)]
    lines = [r"\begin{tabular}{@{}l" + "rr" * len(subjects) + r"rr@{}}", r"\toprule",
             "Config & " + " & ".join(f"\\multicolumn{{2}}{{c}}{{{s}}}" for s in subjects) + r" & Alarms & F1 \\",
             "".join(f"\\cmidrule(lr){{{2 + 2 * i}-{3 + 2 * i}}}" for i in range(len(subjects))),
             " & " + " & ".join(["B", "F"] * len(subjects)) + r" & & \\", r"\midrule"]
    by = {(r["subject"], r["version"], r["config"]): r for r in rows}
    for c in MAIN:
        if c not in head:
            continue
        cells = [fmt((by.get((s, v, c)) or {}).get("detected_rate"), 2) for s in subjects for v in ("buggy", "fixed")]
        lines.append(f"{lab(c)} & " + " & ".join(cells) + f" & {fmt(head[c].get('alarms_buggy_total'), 0)} & "
                     f"{fmt(head[c].get('iris_avg_f1'))} " + r"\\")
    return "\n".join(lines + [r"\bottomrule", r"\end{tabular}", ""])


def numbers_test_tex(head: dict, runs: list) -> str:
    """Macros for held-out test numbers (prefix Test), e.g. \\TestVFourDet."""
    macros = {"TestNumSubjects": str(len({r["subject"] for r in runs})), "TestNumRuns": str(len(runs))}
    for c, tag in (("B1", "BOne"), ("B2", "BTwo"), ("v1", "VOne"), ("iris-like", "Iris"), ("v2", "VTwo"),
                   ("v3", "VThree"), ("v4", "VFour")):
        h = head.get(c) or {}
        macros[f"Test{tag}Det"] = fmt(h.get("cves_detected"), 0)
        macros[f"Test{tag}Rate"] = fmt(h.get("detection_rate_mean"), pct=True)
        macros[f"Test{tag}FDR"] = fmt(h.get("iris_avg_fdr"))
        macros[f"Test{tag}FOne"] = fmt(h.get("iris_avg_f1"))
        macros[f"Test{tag}Alarms"] = fmt(h.get("alarms_buggy_total"), 0)
        macros[f"Test{tag}Diff"] = fmt(h.get("differential_ok"), 0)
    out = ["% Generated by scripts/make_report_assets.py from results/summary/test -- do not edit by hand."]
    out += [f"\\newcommand{{\\{k}}}{{{v}}}" for k, v in sorted(macros.items())]
    return "\n".join(out) + "\n"


def tab_controlled_pairs(rows: list) -> str:
    lines = [r"\begin{tabular}{@{}lrr@{}}", r"\toprule",
             r"Subject & Buggy & Fixed \\", r"\midrule"]
    for subject in ("zt-zip", "spark", "cron-utils", "perfecto-plugin"):
        selected = [r for r in rows if r["subject"] == subject]
        if len(selected) != 3 or any(r["status"] != "completed" for r in selected):
            raise ValueError(f"Controlled replay incomplete for {subject}")
        buggy = sum(float(r["buggy_pretriage_gt"]) for r in selected) / 3
        fixed = sum(float(r["fixed_pretriage_gt"]) for r in selected) / 3
        lines.append(f"{subject} & {buggy:.1f} & {fixed:.1f} " + r"\\")
    return "\n".join(lines + [r"\bottomrule", r"\end{tabular}", ""])


# ------------------------------------------------------------------------------------------ main
def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--results", default="results")
    ap.add_argument("--out", default="report")
    ap.add_argument("--labels", default="labels")
    a = ap.parse_args()
    results, out = Path(a.results), Path(a.out)
    summ = results / "summary"
    head = {r["config"]: r for r in read_csv(summ / "headline.csv")}
    rows = read_csv(summ / "by_config.csv")
    subj = read_csv(summ / "subjects.csv")
    budget = {r["config"]: r for r in read_csv(summ / "budget.csv")}
    runs = load_runs(results)
    labs = {r["config"]: r for r in read_csv(summ / "labels.csv")} if (summ / "labels.csv").exists() else {}
    tot = label_totals(Path(a.labels))
    (out / "figures").mkdir(parents=True, exist_ok=True)
    (out / "tables").mkdir(parents=True, exist_ok=True)
    fig_detection_vs_alarms(head, out / "figures" / "detection_vs_alarms.pdf")
    fig_differential(rows, out / "figures" / "differential.pdf")
    fig_runs(runs, out / "figures" / "runs.pdf")
    if labs:
        fig_label_outcomes(labs, out / "figures" / "label_outcomes.pdf")
    (out / "tables" / "subjects.tex").write_text(tab_subjects(subj))
    (out / "tables" / "headline.tex").write_text(tab_headline(head))
    (out / "tables" / "persubject.tex").write_text(tab_persubject(rows))
    (out / "tables" / "cost.tex").write_text(tab_cost(rows, budget, head))
    (out / "tables" / "numbers.tex").write_text(numbers_tex(head, budget, runs, tot, labs))
    test_summ = summ / "test"
    if (test_summ / "headline.csv").exists():   # held-out test set, kept apart from the development numbers
        test_head = {r["config"]: r for r in read_csv(test_summ / "headline.csv")}
        (out / "tables" / "heldout.tex").write_text(tab_heldout(read_csv(test_summ / "by_config.csv"), test_head))
        (out / "tables" / "numbers_test.tex").write_text(numbers_test_tex(test_head, load_runs(results, test=True)))
    pairs = results / "extensions" / "controlled-pair" / "controlled_pairs.csv"
    if pairs.exists():
        (out / "tables" / "paired.tex").write_text(tab_controlled_pairs(read_csv(pairs)))
    print(f"wrote {out}/figures/*.pdf and {out}/tables/*.tex from {results}")


if __name__ == "__main__":
    main()
