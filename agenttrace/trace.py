"""Traceback over the replication graph (§5.4).

Edges point src -> replica (the direction the content flowed). From an infected
artifact:
  - origin  = earliest internet-sourced ancestor (walk edges backward).
  - scope   = everything downstream (walk edges forward) = files/messages/
              memory to clean up.
networkx carries the graph; we just read the replication table into it.
"""
import networkx as nx


def build_graph(store):
    g = nx.DiGraph()
    for r in store.replications():
        g.add_edge(r["src"], r["replica"], similarity=r["similarity"], directive=r["directive"])
    return g


def _from_internet(store, aid):
    a = store.artifact(aid)
    return bool(a and a["from_internet"])


def analyze(store, infected_id):
    """Return {origin, scope, edges}. origin is the earliest internet source
    reachable backward; scope is all downstream infected artifacts."""
    g = build_graph(store)
    if infected_id not in g:
        return {"origin": infected_id, "scope": [infected_id], "edges": []}

    ancestors = nx.ancestors(g, infected_id) | {infected_id}
    internet = [a for a in ancestors if _from_internet(store, a)]
    # earliest internet source = the one with no internet ancestor of its own
    origin = next((a for a in internet if not (nx.ancestors(g, a) & set(internet))), None)
    origin = origin or (internet[0] if internet else infected_id)

    scope = sorted(nx.descendants(g, origin) | {origin})
    edges = [(u, v, round(d["similarity"], 2)) for u, v, d in g.edges(data=True)
             if u in scope]
    return {"origin": origin, "scope": scope, "edges": edges}
