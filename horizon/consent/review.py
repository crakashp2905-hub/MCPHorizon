"""Mechanical review proxies (P48-08, 12-partial): an IDEAL ATTENTIVE CHECKLIST REVIEWER, a structural faithfulness rubric and a read-only comparison screen.
These measure whether a display CONTAINS the information needed to see a discrepancy. They are not human measurements: reviewer comprehension, time and undue-approval rates (P48-12, P48-13) need real people."""
from .core import canonical
RANK = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "SECRET": 3}


def review(fields, intent):
    """-> (approve, objections). Objects only to what is DISPLAYED and contradicts the intent."""
    obj = []; ok_hosts = set(intent.get("hosts", ())); names = intent.get("names", {})
    if "receivers_hosts" in fields:
        for h in fields["receivers_hosts"]:
            if h not in ok_hosts: obj.append("receiver " + h)
    for n in fields.get("destination_names", ()) or ():
        if names.get(n) not in ok_hosts: obj.append("destination " + n)
    if fields.get("resource_id") and intent.get("artifact") and fields["resource_id"] != intent["artifact"]: obj.append("artifact")
    if fields.get("resource_digest") and intent.get("content") and fields["resource_digest"] != intent["content"]: obj.append("content")
    if fields.get("scope") and intent.get("scope") and fields["scope"] != intent["scope"]: obj.append("scope")
    if fields.get("classification") and RANK.get(fields["classification"], 0) > RANK[intent.get("max_class", "SECRET")]: obj.append("classification")
    if fields.get("amount") is not None and intent.get("max_amount") is not None and fields["amount"] > intent["max_amount"]: obj.append("amount")
    return (not obj), obj


def faithfulness(fields, truth, names_to_hosts):
    """Structural rubric against the true manifest. -> {'correct': n, 'omitted': [...], 'misleading': [...], 'total': n}. Receivers shown as names are resolved with the registry first."""
    tot = ["op", "irreversible", "scope", "classification", "receivers", "resource_id"] + (["resource_digest"] if truth["resource"]["digest"] else []) + (["amount"] if truth["amount"] is not None else [])
    true = {"op": truth["op"], "irreversible": truth["irreversible"], "scope": truth["scope"], "classification": truth["classification"], "resource_id": truth["resource"]["id"], "resource_digest": truth["resource"]["digest"], "amount": truth["amount"]}
    ok, om, mis = 0, [], []
    for k in tot:
        if k == "receivers":
            d = set(fields.get("receivers_hosts", [])) | {names_to_hosts.get(n, n) for n in fields.get("destination_names", [])}; t = {r["host"] for r in truth["receivers"]}
            if not d: om.append(k)
            elif d == t: ok += 1
            elif d < t: om.append(k)
            else: mis.append(k)
        elif k not in fields or fields[k] is None: om.append(k)
        elif fields[k] == true[k]: ok += 1
        else: mis.append(k)
    return {"correct": ok, "omitted": om, "misleading": mis, "total": len(tot)}


def compare_screen(views, truth, names_to_hosts):
    """Read-only side-by-side text screen for sandbox experiments (P48-08): what each display mode shows about the true effect. No controls, no state."""
    modes = list(views); rows = ["FIELD".ljust(16) + "TRUE".ljust(34) + "".join(m.ljust(22) for m in modes)]
    tv = {"op": truth["op"], "irreversible": truth["irreversible"], "scope": truth["scope"], "classification": truth["classification"], "receivers": ",".join(r["host"] for r in truth["receivers"]), "resource_id": truth["resource"]["id"], "resource_digest": truth["resource"]["digest"], "amount": truth["amount"]}
    for k, v in tv.items():
        if v is None: continue
        cells = []
        for m in modes:
            f = views[m]["fields"]
            if k == "receivers": d = set(f.get("receivers_hosts", [])) | {names_to_hosts.get(n, n) for n in f.get("destination_names", [])}; shown = ",".join(sorted(d)) if d else None; tr = set(v.split(",")); mark = "—" if not d else ("ok" if d == tr else ("INCOMPLETE" if d < tr else "DIFF"))
            else: shown = f.get(k); mark = "—" if shown is None else ("ok" if shown == v else "DIFF")
            cells.append(mark.ljust(22))
        rows.append(k.ljust(16) + str(v)[:32].ljust(34) + "".join(cells))
    rows.append("— = not shown   INCOMPLETE = receivers shown are a strict subset of the true ones   DIFF = shown but different from the true effect   (structural check only; not a measure of human understanding)")
    return "\n".join(rows)
