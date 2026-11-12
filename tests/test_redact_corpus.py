"""Shared redaction corpus: the Rust core runs the same file (core/src/redact.rs)."""
import re
from pathlib import Path

import pytest

from shellgate.redact import Redactor

CORPUS = Path(__file__).with_name("redact_corpus.tsv")


def _unesc(x: str) -> str:
    return x.replace("\\n", "\n").replace("\\t", "\t")


def _rows():
    for line in CORPUS.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            name, inp, exp = line.split("\t")
            yield pytest.param(_unesc(inp), _unesc(exp), id=name)


@pytest.mark.parametrize("inp,exp", list(_rows()))
def test_corpus(inp, exp):
    r = Redactor(True, ["example.com"], secrets=["known-secret-value-123456"])
    assert re.sub(r"<mac:[0-9a-f]{6}>", "<mac>", r.text(inp)[0]) == exp


def test_pii_off_keeps_personal_data():
    r = Redactor(True, [], pii=False)
    s = "mail alice@gmail.com tel 13812345678 SSID: Home-5G"
    assert r.text(s)[0] == s


def test_short_known_secret_ignored():
    r = Redactor(True, [], secrets=["short"])
    assert r.text("a short word")[0] == "a short word"
