"""문장 변형 웜을 잡기 위한 의미 유사도 (제안서 §6 "임베딩으로 보완").

백엔드는 선택적:
  - `sentence-transformers`가 설치돼 있으면 다국어 임베딩 모델을 씀(동의어·바꿔쓰기에 강함).
  - 없으면 stdlib 해싱 벡터(bag-of-tokens 코사인)로 폴백 — torch 2GB를 강요하지 않으면서
    난독화/재배열에는 difflib보다 강함. 동의어까지 잡으려면 모델 설치.

difflib이 1차(빠름), 이 코사인이 2차 보완(engine에서 임계 미달 시 재시도).
"""
import os
import re
import math
import hashlib

from .fingerprint import normalize

_DIM = 256
_TOKEN = re.compile(r"\w+", re.UNICODE)
_model = None          # lazy; False면 폴백 확정


def _tokens(text):
    return _TOKEN.findall(normalize(text))


def _hash_vector(text):
    """stdlib 폴백: 토큰을 해시 인덱스에 누적한 L2 정규화 bag-of-tokens 벡터."""
    v = [0.0] * _DIM
    for tok in _tokens(text):
        h = int(hashlib.sha256(tok.encode()).hexdigest(), 16)
        v[h % _DIM] += 1.0 if (h >> 8) & 1 else -1.0   # 부호 해싱으로 충돌 상쇄
    n = math.sqrt(sum(x * x for x in v))
    return [x / n for x in v] if n else v


def _load_model():
    """있으면 로드, 없으면 False. AGENTTRACE_EMBED_MODEL로 모델명 지정."""
    global _model
    if _model is None:
        try:
            from sentence_transformers import SentenceTransformer
            name = os.environ.get("AGENTTRACE_EMBED_MODEL",
                                  "paraphrase-multilingual-MiniLM-L12-v2")
            _model = SentenceTransformer(name)
        except Exception:
            _model = False      # 폴백 확정
    return _model


def embed(text):
    m = _load_model()
    if m:
        return m.encode(normalize(text), normalize_embeddings=True).tolist()
    return _hash_vector(text)


def cosine(a, b):
    return sum(x * y for x, y in zip(a, b))   # 둘 다 L2 정규화됨 → 내적 = 코사인


def similar(a, b):
    """두 텍스트의 의미 유사도 0..1 (음수는 0으로 절단)."""
    return max(0.0, cosine(embed(a), embed(b)))
