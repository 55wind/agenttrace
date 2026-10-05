"""Traceback over the replication graph (§5.4).

Edges point src -> replica (the direction the content flowed). From an infected
artifact:
  - origin  = earliest internet-sourced ancestor (walk edges backward).
  - scope   = everything downstream (walk edges forward) = files/messages/
              memory to clean up.

ponytail: the graph is one PC's replication history (tens of nodes), so a
stdlib BFS over adjacency dicts replaces networkx entirely — no scipy/numpy,
no 80MB in the packaged app. Swap back to networkx only if graph algorithms
beyond reachability are ever needed.
"""


def _edges(store):
    return [(r["src"], r["replica"], r["similarity"]) for r in store.replications()]


def _reach(adj, start):
    """BFS reachable set from start (exclusive of start)."""
    seen, queue = set(), list(adj.get(start, []))
    while queue:
        n = queue.pop()
        if n in seen:
            continue
        seen.add(n)
        queue.extend(adj.get(n, []))
    return seen


def analyze(store, infected_id):
    """Return {origin, scope, edges}. origin is the earliest internet source
    reachable backward; scope is all downstream infected artifacts."""
    edges = _edges(store)
    succ, pred, nodes = {}, {}, set()
    for u, v, _ in edges:
        succ.setdefault(u, []).append(v)
        pred.setdefault(v, []).append(u)
        nodes.update((u, v))

    if infected_id not in nodes:
        return {"origin": infected_id, "scope": [infected_id], "edges": []}

    ancestors = _reach(pred, infected_id) | {infected_id}
    internet = {a for a in ancestors if _from_internet(store, a)}
    # earliest internet source = one with no internet ancestor of its own
    origin = next((a for a in internet if not (_reach(pred, a) & internet)), None)
    origin = origin or (next(iter(internet)) if internet else infected_id)

    scope = sorted(_reach(succ, origin) | {origin})
    scope_set = set(scope)
    out = [(u, v, round(sim, 2)) for u, v, sim in edges if u in scope_set]
    return {"origin": origin, "scope": scope, "edges": out}


def _from_internet(store, aid):
    a = store.artifact(aid)
    return bool(a and a["from_internet"])
