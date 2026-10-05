"""Shared fixtures. Tests needing a JDK or Tai-e skip themselves when the tool is missing."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from nesy.config import load_settings  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "minizip"
DATA = ROOT / "tests" / "data"


@pytest.fixture(scope="session")
def settings():
    return load_settings()


def _jdk17(settings):
    j = settings.java17_home()
    return j if j and (Path(j) / "bin" / "javac").exists() else None


@pytest.fixture(scope="session")
def javac(settings):
    j = _jdk17(settings)
    if not j:
        pytest.skip("JDK 17+ with javac not found (set JAVA17_HOME)")
    return str(Path(j) / "bin" / "javac")


@pytest.fixture(scope="session")
def built_fixture(settings, javac):
    """Compile tests/fixtures/minizip (library jar + app classes)."""
    from nesy.cli import build_fixture
    build_fixture(settings, FIXTURE)
    return FIXTURE / "build"


@pytest.fixture(scope="session")
def fixture_facts(built_fixture, settings):
    # The spec/facts tests need the JDK 8 library on the fact path (e.g. to resolve argument arities
    # for V2's index checks). Without it the facts differ, so skip cleanly instead of failing oddly.
    if not settings.jre8_jars():
        pytest.skip("JDK 8 library (rt.jar) not found; set JAVA8_HOME")
    from nesy.facts import extract_facts
    return extract_facts([built_fixture / "app"], [built_fixture / "acme-util.jar"], settings.jre8_jars(),
                         [FIXTURE / "app" / "src"])


@pytest.fixture
def tmp_work(tmp_path):
    return tmp_path


def taie_available(settings) -> bool:
    jar = ROOT / (settings.section("taie").get("jar") or "tools/tai-e-all-0.5.4.jar")
    return jar.exists() and _jdk17(settings) is not None and bool(settings.jre8_jars())
