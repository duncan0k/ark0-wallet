#!/usr/bin/env python3
"""The checks of the privnet build against the private network that privnet.py made (README.md).

Each wallet step runs the privnet_e2e test of the wallet crate (src/privnet_e2e.rs) with the feature on, through
the wallet's command layer; each answer, and the nodes' answers, go to $PRIVNET_DIR/evidence/, and a summary to
$PRIVNET_DIR/evidence/results.json.

    checks.py all            every check, in order, on a network fresh from `privnet.py setup`
    checks.py <n> ...        only these (they expect the network as the checks before them leave it)

Environment: as privnet.py, and PRIVNET_WALLET_SRC (the wallet's src-tauri directory).
"""
import json
import os
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import privnet  # noqa: E402
from privnet import H4T, MARGIN, cli, mine, path  # noqa: E402

WALLET_SRC = os.environ.get("PRIVNET_WALLET_SRC", "")
# Seconds a person takes before each step and between a plan and its confirmation. The site lets one visitor
# (here every step, from 127.0.0.1) look up 20 addresses at once and one a second after that; a refresh looks
# up 7 here, a plan 7 and its confirmation 13 more (README.md, "The site's limits").
PACE = int(os.environ.get("PRIVNET_PACE", "25"))
OPENS = H4T + MARGIN
RESULTS = {}


def evidence(name):
    os.makedirs(path("evidence"), exist_ok=True)
    return path("evidence", name)


def record(check, ok, summary, **facts):
    RESULTS[check] = {"ok": ok, "summary": summary, **facts}
    with open(evidence("results.json"), "w") as f:
        json.dump(RESULTS, f, indent=2)
    print(f"{'PASS' if ok else 'FAIL'} {check}: {summary}", flush=True)


def step(name, label, wallet="wallet-created", config="wallet-ab.json", signal=None, **args):
    """One wallet step; its JSON answer."""
    out = evidence(f"{label}.json")
    env = dict(os.environ, ARK0_PRIVNET_CONFIG=path(config), ARK0_PRIVNET_WALLET_DIR=path(wallet),
               ARK0_PRIVNET_STEP=name, ARK0_PRIVNET_ARGS=json.dumps(args), ARK0_PRIVNET_OUT=out)
    if signal:
        env["ARK0_PRIVNET_SIGNAL"] = signal
    env["ARK0_PRIVNET_PACE"] = str(PACE)
    os.makedirs(path(wallet), exist_ok=True)
    time.sleep(PACE)
    run = subprocess.run(["cargo", "test", "--locked", "-j", "4", "--features", "privnet", "--lib", "--",
                          "--exact", "app::privnet_e2e::privnet_e2e", "--nocapture"],
                         cwd=WALLET_SRC, env=env, capture_output=True, text=True)
    if run.returncode != 0:
        with open(evidence(f"{label}.log"), "w") as f:
            f.write(run.stdout + run.stderr)
        raise SystemExit(f"step {label} failed; see {evidence(label + '.log')}")
    with open(out) as f:
        return json.load(f)["answer"]


def mempool_has(n, txid):
    out = cli(n, "getmempoolentry", txid, check=False)
    return not isinstance(out, tuple)


def confirmations(n, txid):
    tx = cli(n, "getrawtransaction", txid, 1, check=False)
    return tx.get("confirmations", 0) if isinstance(tx, dict) else None


def tip():
    return cli("n1", "getblockcount")


def mine_to(height):
    if tip() < height:
        mine(height - tip())
    return tip()


def pq2(answer):
    view = answer["ok"]["pq2"]
    return {k: view[k] for k in ("blocked", "allowed", "spend_allowed", "opens_at", "mldsa44_allowed", "mldsa_disabled", "spendable", "pending", "incoming")}


def node_address():
    return cli("n1", "getnewaddress", wallet="funds")


def check1():
    mine_to(OPENS - 2)
    seen = []
    for label in ("c1-below", "c1-just-below"):
        overview = step("overview", f"{label}-overview")
        address = step("address", f"{label}-address")
        seen.append({"tip": overview["ok"]["chain"]["tip"], "pq2": pq2(overview), "address": address["address"]})
        if label == "c1-below":
            mine_to(OPENS - 1)
    ok = all(s["pq2"]["blocked"] == "waiting" and s["pq2"]["opens_at"] == OPENS and s["address"] == {"error": "pq2_waiting"} for s in seen)
    record("1", ok, f"at tips {seen[0]['tip']} and {seen[1]['tip']}: blocked 'waiting', opens_at {OPENS}, new address refused 'pq2_waiting'", seen=seen)


def check3():
    """One source the node that has not upgraded (site C on n3), at H4T + 6."""
    mine_to(OPENS)
    overview = step("overview", "c3-overview", wallet="wallet-ac", config="wallet-ac.json")
    address = step("address", "c3-address", wallet="wallet-ac", config="wallet-ac.json")
    c_state = json.loads(subprocess.run(["curl", "-s", f"http://127.0.0.1:{privnet.SITES['C'][1]}/api/state"], capture_output=True, text=True).stdout)
    view = overview["ok"]
    ok = (address["address"] == {"error": "pq2_source_not_upgraded"} and view["pq2"] is not None
          and view["pq2"]["blocked"] == "source_not_upgraded" and not view["pq2"]["allowed"])
    record("3", ok, f"tip {view['chain']['tip'] if view['chain'] else None}; sources A and C: pq2 {view['pq2'] and pq2(overview)}; new address {address['address']}",
           c_deployments=c_state.get("deployments"), c_lattice=(c_state.get("tripwire") or {}).get("lattice"),
           chain=view["chain"], problem=view["problem"], address=address)


def check2():
    mine_to(OPENS)
    addresses = []
    for i in range(3):
        a = step("address", f"c2-address-{i}")
        addresses.append(a["address"])
    ok_issue = all("ok" in a for a in addresses)
    payments = {}
    for i, a in enumerate(addresses):
        if "ok" in a:
            payments[a["ok"]["address"]] = privnet.pay(a["ok"]["address"], "0.003")
    before = step("overview", "c2-overview-mempool")
    mined = mine(1)
    after = step("overview", "c2-overview-confirmed")
    coins = [{"address": a["address"], "index": a["index"], "spendable": a["spendable"], "coins": a["coins"]} for a in after["ok"]["pq2"]["addresses"]]
    ok = ok_issue and len(coins) == 3 and all(c["spendable"] == 300_000 and c["coins"][0]["status"] == "protected" for c in coins)
    with open(evidence("c2-addresses.json"), "w") as f:
        json.dump([a["ok"] for a in addresses if "ok" in a], f, indent=2)
    record("2", ok, f"at tip {OPENS}: addresses {[a.get('ok', a).get('index', a) for a in addresses]} issued; paid 0.003 each; "
           f"the wallet saw {before['ok']['pq2']['incoming']} sat incoming, then {after['ok']['pq2']['spendable']} sat spendable at {mined}",
           addresses=addresses, payments=payments, incoming=pq2(before), confirmed=coins)


def addresses_of_check2():
    with open(evidence("c2-addresses.json")) as f:
        return [a["address"] for a in json.load(f)]


def spend_and_confirm(check, label, frm, path_name):
    to = node_address()
    answer = step("send", label, to=to, amount="0.001", **({"from": frm}), **({"path": path_name} if path_name else {}))
    plan, sent = answer["plan"], answer.get("send", {})
    txid = sent.get("ok", {}).get("txid")
    accepted = {n: mempool_has(n, txid) for n in ("n1", "n2")} if txid else {}
    mined = mine(1) if txid else None
    confirmed = {n: confirmations(n, txid) for n in ("n1", "n2")} if txid else {}
    result = sent.get("ok", {}).get("result")
    return plan, sent, txid, accepted, mined, confirmed, result


def check4():
    a0 = addresses_of_check2()[0]
    plan, sent, txid, accepted, mined, confirmed, result = spend_and_confirm("4", "c4-send", a0, None)
    ok = bool(txid) and plan.get("signature") == "slhdsa128s" and all(accepted.values()) and all(c == 1 for c in confirmed.values())
    record("4", ok, f"leaf B (signature {plan.get('signature')}, {plan.get('pq2', {}).get('witness_bytes')} witness bytes): {txid}, "
           f"in the mempool of n1/n2 {accepted}, confirmed at {mined} {confirmed}", plan=plan, result=result, txid=txid)


def check5():
    a1 = addresses_of_check2()[1]
    plan, sent, txid, accepted, mined, confirmed, result = spend_and_confirm("5", "c5-send", a1, "mldsa44")
    ok = bool(txid) and plan.get("signature") == "mldsa44" and all(accepted.values()) and all(c == 1 for c in confirmed.values())
    record("5", ok, f"leaf A (signature {plan.get('signature')}, {plan.get('pq2', {}).get('witness_bytes')} witness bytes): {txid}, "
           f"in the mempool of n1/n2 {accepted}, confirmed at {mined} {confirmed}", plan=plan, result=result, txid=txid)


def check6():
    a2 = addresses_of_check2()[2]
    signal = path("signal")
    os.makedirs(signal, exist_ok=True)
    for f in ("held-ready", "held-go"):
        if os.path.exists(os.path.join(signal, f)):
            os.remove(os.path.join(signal, f))
    to = node_address()
    held = {}
    thread = threading.Thread(target=lambda: held.update(step("held", "c6-held", signal=signal, to=to, amount="0.001", path="mldsa44", **{"from": a2})))
    thread.start()
    for _ in range(3000):
        if os.path.exists(os.path.join(signal, "held-ready")) or not thread.is_alive():
            break
        time.sleep(0.2)
    state_before = cli("n1", "gettripwireinfo")["lattice"]
    drill_txid = privnet.drill()
    drill_block = mine(1)
    state_after = {n: cli(n, "gettripwireinfo").get("lattice") if n != "n3" else None for n in privnet.NODES}
    with open(os.path.join(signal, "held-go"), "w") as f:
        f.write("go\n")
    thread.join()
    send = held.get("send", {})
    result = send.get("ok", {}).get("result")
    rebuilt = send.get("ok", {}).get("rebuilt")
    held_txid = send.get("ok", {}).get("txid")
    rebuilt_send = held.get("rebuilt_send", {})
    rebuilt_txid = rebuilt_send.get("ok", {}).get("txid")
    accepted = {n: mempool_has(n, rebuilt_txid) for n in ("n1", "n2")} if rebuilt_txid else {}
    # What the node itself says of the held spend: the wallet's record of it, and testmempoolaccept is not
    # possible without its hex; the API passed the node's reason on.
    mined = mine(1) if rebuilt_txid else None
    confirmed = {n: confirmations(n, rebuilt_txid) for n in ("n1", "n2")} if rebuilt_txid else {}
    overview = step("overview", "c6-offers-overview")
    # Asked for ML-DSA-44 from an address that still holds coins (the held coin may have gone in the rebuild).
    holding = next(a["address"] for a in overview["ok"]["pq2"]["addresses"] if a["spendable"] > 0)
    offers = step("plan", "c6-offers-plan", to=to, amount="0.0005", path="mldsa44", **{"from": holding})
    reason = result.get("reason") if isinstance(result, dict) and result.get("kind") == "rejected" else None
    # The node adds the input and the transaction after its message.
    expected = "mempool-script-verify-flag-failed (ML-DSA-44 signature checks are disabled in this leaf)"
    reason_ok = bool(reason) and (reason == expected or reason.startswith(expected + ", "))
    no_ml = overview["ok"]["pq2"]["mldsa44_allowed"] is False and offers.get("ok", {}).get("signature") == "slhdsa128s"
    # A rebuild that came with the refusal must confirm; without one, check 6b takes it from the activity view.
    ok = reason_ok and no_ml and (not rebuilt_txid or all(c == 1 for c in confirmed.values()))
    record("6", ok, f"drill {drill_txid} at {drill_block}; held leaf-A spend {held_txid}: {result}; ML-DSA-44 offered after: "
           f"{overview['ok']['pq2']['mldsa44_allowed']} (plan asked for it: {offers.get('ok', {}).get('signature')}, reason {offers.get('ok', {}).get('pq2', {}).get('mldsa44_reason')}); "
           f"rebuild with the refusal: {rebuilt_txid or held.get('rebuild_at_once')}, mempool {accepted}, confirmed at {mined} {confirmed}",
           drill=drill_txid, drill_block=drill_block, lattice_before=state_before, lattice_after=state_after, held=held,
           offers=offers, overview_pq2=pq2(overview))


def check7():
    overview = step("overview", "c7-overview", wallet="wallet-legacy", legacy=True)
    address = step("address", "c7-address", wallet="wallet-legacy", legacy=True)
    view = overview["ok"]["pq2"]
    ok = view["blocked"] == "legacy" and "error" in address["address"]
    record("7", ok, f"backup-code wallet: pq2 blocked {view['blocked']!r}, allowed {view['allowed']}; new address {address['address']}",
           pq2=pq2(overview), address=address)


def wait_sites(height):
    """Until sites A and B report this tip: the site keeps its view of the node for five seconds."""
    for _ in range(200):
        blocks = []
        for site in "AB":
            try:
                body = subprocess.run(["curl", "-s", f"http://127.0.0.1:{privnet.SITES[site][1]}/api/state"], capture_output=True, text=True).stdout
                blocks.append(json.loads(body).get("blocks"))
            except ValueError:
                blocks.append(None)
        if blocks == [height, height]:
            return
        time.sleep(0.1)
    raise SystemExit(f"the sites did not reach {height}")


def check8():
    height = tip()
    invalidated = privnet.on_every_node("invalidateblock", OPENS)
    wait_sites(OPENS - 1)
    below = step("overview", "c8-overview-invalidated")
    address_below = step("address", "c8-address-invalidated")
    reconsidered = privnet.on_every_node("reconsiderblock", OPENS)
    privnet.wait_synced(privnet.network(), height)
    wait_sites(height)
    above = step("overview", "c8-overview-reconsidered")
    address_above = step("address", "c8-address-reconsidered")
    ok = (below["ok"]["pq2"]["blocked"] == "waiting" and address_below["address"] == {"error": "pq2_waiting"}
          and above["ok"]["pq2"]["blocked"] is None and "ok" in address_above["address"])
    record("8", ok, f"invalidateblock {OPENS} on every node: tip {below['ok']['chain']['tip']}, pq2 blocked {below['ok']['pq2']['blocked']!r}, "
           f"new address {address_below['address']}; reconsiderblock: tip {above['ok']['chain']['tip']}, blocked {above['ok']['pq2']['blocked']!r}, "
           f"new address {address_above['address']}", invalidated=invalidated, reconsidered=reconsidered,
           below=pq2(below), above=pq2(above))


def check6b():
    """After check 6, when the wallet offered no rebuild with the refusal: the activity view's offer, and the
    rebuild through leaf B of the same coin, confirmed."""
    held = RESULTS["6"]["held"]
    if held.get("rebuilt_send"):
        return record("6b", True, "the rebuild came with the refusal and was confirmed in check 6")
    held_txid = held["send"]["ok"]["txid"]
    coin = next(r["outpoints"] for r in held["records"] if r["txid"] == held_txid)
    activity = step("activity", "c6b-activity")
    item = next(a for a in activity["ok"] if a["txid"] == held_txid)
    offers = step("plan", "c6b-offers-plan", to=node_address(), amount="0.0005", path="mldsa44", **{"from": item["address"]})
    rebuild = step("rebuild", "c6b-rebuild", txid=held_txid, confirm=True)
    sent = rebuild.get("send", {}).get("ok", {})
    txid = sent.get("txid")
    spent = cli("n1", "getrawtransaction", txid, 1)["vin"] if txid else []
    same_coin = [f"{i['txid']}:{i['vout']}" for i in spent] == coin
    accepted = {n: mempool_has(n, txid) for n in ("n1", "n2")} if txid else {}
    mined = mine(1) if txid else None
    confirmed = {n: confirmations(n, txid) for n in ("n1", "n2")} if txid else {}
    ok = (item["rebuild"] is True and offers.get("ok", {}).get("signature") == "slhdsa128s"
          and offers["ok"]["pq2"]["mldsa44_reason"] == "disabled" and rebuild["plan"].get("signature") == "slhdsa128s"
          and same_coin and sent.get("result", {}).get("kind") == "sent" and all(c == 1 for c in confirmed.values()))
    record("6b", ok, f"activity offers a rebuild of {held_txid}: {item['rebuild']}; a plan asking for ML-DSA-44 from {item['address'][:16]}...: "
           f"{offers.get('ok', {}).get('signature')} ({offers.get('ok', {}).get('pq2', {}).get('mldsa44_reason')}); the rebuild through leaf B "
           f"{txid} spends the same coin {coin}: {same_coin}; mempool {accepted}; confirmed at {mined} {confirmed}",
           activity_item=item, offers=offers, rebuild=rebuild, txid=txid)


def check10():
    """Below H4T + 6: a restored wallet's scan keeps its empty pq2 addresses, and a payment from its funded
    ML-DSA-44 account to one of them is refused (no pq2 output before pq2 opens)."""
    mine_to(OPENS - 4)
    scan = step("scan", "c10-scan", wallet="wallet-gate", restore=True)
    overview = step("overview", "c10-overview", wallet="wallet-gate", restore=True)
    mldsa44 = next(a["address"] for a in overview["ok"]["accounts"] if a["kind"] == "mldsa44")
    funding = privnet.pay(mldsa44, "0.002")
    mined = mine(1)
    kept = step("overview", "c10-overview-funded", wallet="wallet-gate", restore=True)
    spendable = next(a["spendable"] for a in kept["ok"]["accounts"] if a["kind"] == "mldsa44")
    with open(path("wallet-gate", "pq2.json")) as f:
        book = json.load(f)
    reserved = sorted(int(i) for i in book["chains"][0]["addresses"] if int(i) not in book["chains"][0]["handed_out"])
    to = book["chains"][0]["addresses"][str(reserved[3])]
    plan = step("plan_account", "c10-plan", wallet="wallet-gate", restore=True, kind="mldsa44", to=to, amount="0.001")
    ok = (scan.get("scan", {}).get("ok") is not None and spendable == 200_000 and tip() < OPENS
          and plan == {"error": "destination_not_ready"})
    record("10", ok, f"tip {tip()} (below {OPENS}): scan {scan.get('scan')}, ML-DSA-44 account funded {funding} at {mined} "
           f"({spendable} sat); a payment from it to kept pq2 index {reserved[3]}: {plan}",
           scan=scan, funding=funding, kept_index=reserved[3], to=to, plan=plan)


def check9():
    """At H4T + 6, after check 2: the same words restored on another device (not made here). Its recovery scan
    completes within the site's limits, finds every index check 2 paid, and an address is then issued."""
    paid = addresses_of_check2()
    scan = step("scan", "c9-scan", wallet="wallet-restored", restore=True)
    overview = step("overview", "c9-overview", wallet="wallet-restored", restore=True)
    address = step("address", "c9-address", wallet="wallet-restored", restore=True)
    result = scan.get("scan", {}).get("ok", {})
    seen = {a["address"]: a["spendable"] for a in overview["ok"]["pq2"]["addresses"]}
    ok = (bool(result) and result.get("found") == len(paid) and all(seen.get(a) == 300_000 for a in paid)
          and "ok" in address["address"] and address["address"]["ok"]["index"] == result["issued"][0])
    record("9", ok, f"restored from its words at tip {overview['ok']['chain']['tip']}: scan {result or scan.get('scan')} in "
           f"{scan.get('seconds', 0):.1f} s; coins seen on {sorted(seen.values())}; then address {address['address']}",
           seconds=scan.get("seconds"), scan=scan, pq2=pq2(overview), address=address)


CHECKS = {"10": check10, "1": check1, "3": check3, "2": check2, "9": check9, "4": check4, "5": check5, "6": check6, "6b": check6b, "7": check7, "8": check8}


def main():
    if not WALLET_SRC:
        raise SystemExit("set PRIVNET_WALLET_SRC")
    if os.path.exists(evidence("results.json")):
        with open(evidence("results.json")) as f:
            RESULTS.update(json.load(f))
    wanted = list(CHECKS) if sys.argv[1:] == ["all"] else sys.argv[1:]
    for c in wanted:
        CHECKS[c]()


if __name__ == "__main__":
    main()
