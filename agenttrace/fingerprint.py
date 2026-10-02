"""Content fingerprinting and directive scoring — stdlib only.

- normalize(): NFKC + strip invisible/zero-width chars + collapse whitespace,
  so an attacker can't dodge a hash with a zero-width space or odd casing.
- fingerprint(): sha256 of the normalized text = the artifact id.
- similarity(): difflib ratio on normalized text.
  ponytail: O(n) pairwise difflib, fine for a single PC's history. Swap in
  MinHash/LSH (datasketch) if the artifact table grows past ~10k rows.
- directive_score(): regex/keyword rules for "injection-shaped" instructions.
"""
import re
import hashlib
import unicodedata
from difflib import SequenceMatcher

# zero-width / invisible chars attackers use to perturb content
_INVISIBLE = re.compile(r"[​-‏‪-‮⁠﻿]")
_WS = re.compile(r"\s+")


def normalize(text):
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE.sub("", text)
    return _WS.sub(" ", text).strip().lower()


def fingerprint(text):
    return hashlib.sha256(normalize(text).encode()).hexdigest()


def similarity(a, b):
    return SequenceMatcher(None, normalize(a), normalize(b)).ratio()


# directive patterns: imperative propagation + fake-system framing.
# Deliberately multilingual (ko/en) because injected content often is.
_DIRECTIVE = [
    r"\b(copy|forward|include|send|append|paste|replicate|propagate)\b.{0,30}\b(this|following|message|text|instruction)\b",
    r"(복사|전달|포함|첨부|붙여넣|그대로)\s*(해|하라|하세요|할것|할 것)",
    r"(ignore|disregard)\b.{0,20}\b(previous|above|prior)\b.{0,20}\binstruction",
    r"(이전|위의)\s*지시.{0,10}(무시|잊)",
    r"(system\s*:|<\s*system\s*>|you are now|from now on you)",  # fake system framing
    r"(가짜|시스템)\s*(지시|프롬프트|명령)",
]
_DIRECTIVE = [re.compile(p, re.I) for p in _DIRECTIVE]


def directive_score(text):
    """0..1 — fraction of directive patterns present. Any hit is suspicious."""
    n = normalize(text)
    hits = sum(1 for p in _DIRECTIVE if p.search(n))
    return hits / len(_DIRECTIVE)
