"""Monitor — what the agent hooks drive at runtime.

Flow per the proposal (§5.4):
  record_read  -> fingerprint, store, taint the session if the content is
                  from the internet or already infected.
  record_write -> fingerprint, store, and run replication detection:
                  similarity AND directive-shape AND a following high-risk
                  action => this write is a self-replication; mark it infected.
  guard        -> judge an action before it runs, using taint state.
"""
from . import fingerprint as fp
from .guard import Guard

# replication fires only when all three hold (§5.4). directive is the knob that
# keeps a normal quoted reply (directive≈0) from being flagged.
SIM_THRESHOLD = 0.80
EMBED_THRESHOLD = 0.75              # 2차 보완: difflib 미달 시 의미 유사도로 변형 웜 포착
DIRECTIVE_THRESHOLD = 0.16          # >= 1 of the directive patterns present
HIGH_RISK = {"send", "exec", "autorun", "persist", "write"}


class Monitor:
    def __init__(self, store, guard=None):
        self.store = store
        self.guard = guard or Guard()
        # session -> list of (artifact_id, text). ponytail: in-memory cache;
        # rebuild from read events on restart if long-lived sessions matter.
        self._reads = {}
        self._tainted = set()

    # --- ingestion ---
    def record_read(self, session, agent, text, kind="file", location="", from_internet=False):
        aid = fp.fingerprint(text)
        self.store.upsert_artifact(aid, kind, location, from_internet)
        self.store.append("read", {"artifact": aid, "location": location}, session, agent)
        art = self.store.artifact(aid)
        if from_internet or (art and art["infected"]):
            self._tainted.add(session)
            self.store.set_flag(aid, tainted=True)
        self._reads.setdefault(session, []).append((aid, text))
        return aid

    def record_write(self, session, agent, text, kind="file", location="", next_action="persist"):
        aid = fp.fingerprint(text)
        self.store.upsert_artifact(aid, kind, location)
        eid = self.store.append(
            "write", {"artifact": aid, "location": location, "next": next_action},
            session, agent,
        )
        self._detect_replication(session, aid, text, next_action, eid)
        return aid

    def is_tainted(self, session):
        return session in self._tainted

    def guard_action(self, session, agent, action, content):
        verdict, reason = self.guard.evaluate(action, content, tainted=self.is_tainted(session))
        self.store.append(
            "verdict", {"action": action, "verdict": verdict, "reason": reason, "content": content[:200]},
            session, agent,
        )
        return verdict, reason

    # --- detection ---
    def _detect_replication(self, session, replica_id, text, next_action, eid):
        d = fp.directive_score(text)
        if d < DIRECTIVE_THRESHOLD or next_action not in HIGH_RISK:
            return
        for src_id, src_text in self._reads.get(session, []):
            if src_id == replica_id:
                continue
            sim = fp.similarity(src_text, text)
            if sim < EMBED_THRESHOLD:                     # 변형 웜 보완: 의미 유사도 2차 확인
                from . import embedding
                sim = max(sim, embedding.similar(src_text, text))
            if sim >= EMBED_THRESHOLD:
                self.store.add_replication(src_id, replica_id, sim, d, next_action, eid)
                newly = not self.store.artifact(replica_id)["infected"]
                self.store.set_flag(replica_id, infected=True)
                self.store.set_flag(src_id, infected=True)   # 전파 원본(페이로드 운반체)도 감염으로 집계
                if newly:
                    # open a stub incident; trace.analyze fills origin+scope on query
                    self.store.add_incident("replication", [eid], src_id, [replica_id])
                return
