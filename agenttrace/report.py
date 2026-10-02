"""4-part incident report (§3.6): 관찰 사실 / 가능한 해석 / 판단 한계 / 사용자 조치.

Rule-based templates so it works offline. The LLM in the proposal only
rephrases these facts for readability — judgment stays with the rules/graph —
so swapping in an LLM here is optional, not required.
"""
from . import trace


def incident_report(store, incident_row):
    src = incident_row["source"]
    result = trace.analyze(store, src) if src else {"origin": None, "scope": [], "edges": []}
    origin, scope = result["origin"], result["scope"]
    o = store.artifact(origin) if origin else None

    facts = [
        f"복제 규칙 '{incident_row['rule']}' 발동 (근거 이벤트 {incident_row['evidence']}).",
        f"최초 감염원: {o['location'] if o else origin} "
        f"(인터넷 유입: {'예' if o and o['from_internet'] else '불명'}).",
        f"감염 범위: {len(scope)}개 artifact — {', '.join(_loc(store, a) for a in scope)}.",
    ]
    interp = ["유입 콘텐츠의 지시문이 에이전트 출력으로 재등장 후 고위험 행동이 이어짐 → 자가복제 전파로 해석됨."]
    limits = [
        "지시문을 바꿔 쓴 변형 웜은 유사도 기준 미달로 누락될 수 있음(임베딩 보완 필요).",
        "에이전트 자기 보고가 아닌 OS·훅 기록 기반이나, 훅 미적용 경로는 사후 탐지만 가능.",
    ]
    actions = [f"정리 대상: {_loc(store, a)}" for a in scope] + \
              ["원본은 화면에서 직접 열람하고, 외부 전송 전 검역할 것."]
    return {"관찰 사실": facts, "가능한 해석": interp, "판단 한계": limits, "사용자 조치": actions}


def _loc(store, aid):
    a = store.artifact(aid)
    return (a["location"] or aid[:12]) if a else aid[:12]


def render(report):
    out = []
    for section, lines in report.items():
        out.append(f"[{section}]")
        out.extend(f"  - {ln}" for ln in lines)
    return "\n".join(out)
