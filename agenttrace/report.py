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
        f"복제 규칙이 발동했습니다 (근거 기록 {incident_row['evidence']}).",
        f"최초 감염원은 ‘{o['location'] if o else origin}’이며, "
        f"인터넷에서 {'들어왔습니다' if o and o['from_internet'] else '들어왔는지 불명확합니다'}.",
        f"감염 범위는 {len(scope)}곳입니다. {', '.join(_loc(store, a) for a in scope)}.",
    ]
    interp = ["유입된 내용의 지시문이 에이전트 출력에 다시 나타난 뒤 고위험 행동으로 "
              "이어졌습니다. 스스로 복제되어 퍼진 것으로 보입니다."]
    limits = [
        "지시문을 바꿔 쓴 변형 웜은 닮음 기준에 못 미쳐 놓칠 수 있습니다. 임베딩으로 보완합니다.",
        "에이전트 자기 보고가 아니라 OS와 훅 기록에 근거하지만, 훅이 없는 경로는 사후에만 탐지합니다.",
    ]
    actions = [f"‘{_loc(store, a)}’ 을(를) 격리하거나 삭제하세요." for a in scope] + \
              ["원본은 화면에서 직접 열어 보고, 외부로 보내기 전에 검역하세요."]
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
