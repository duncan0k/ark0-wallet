#!/usr/bin/env python3
"""A private signet for the privnet build of the desktop wallet (see README.md).

Three nodes of the verified ark0-node-m4tb release on one machine: n1 and n2 run the M4 rules (the lattice
tripwire included), n3 runs without -signetlatticetripwire, as a source that has not upgraded. Each has a
copy of the site's wallet API in front of it (A, B and C). Blocks are signed with a key the harness holds
(a 1-of-1 multisig challenge, as on Ark-0) and made by contrib/signet/miner of the matching source tree.

    privnet.py setup                 make the chain: coins, tripwires, the M4 heights; start everything
    privnet.py start | stop          the nodes and the sites
    privnet.py mine N                N blocks
    privnet.py pay ADDRESS BTC       a payment from the nodes' wallet (not mined)
    privnet.py drill                 spend the drill lattice tripwire (not mined)
    privnet.py invalidate HEIGHT     invalidateblock at HEIGHT on every node
    privnet.py reconsider HEIGHT     reconsiderblock at HEIGHT on every node
    privnet.py cli NODE ARGS...      bitcoin-cli on n1, n2 or n3
    privnet.py info                  the network file

Environment: PRIVNET_BIN (the release's bin/), PRIVNET_SRC (Bitcoin Core v31.1 with the release's patch
series applied: contrib/signet/miner and test/functional/test_framework), PRIVNET_SITE (the site's web/
directory), PRIVNET_DIR (a new, empty working directory).
"""
import json
import os
import subprocess
import sys
import time
import urllib.request

BIN = os.environ.get("PRIVNET_BIN", "")
SRC = os.environ.get("PRIVNET_SRC", "")
SITE = os.environ.get("PRIVNET_SITE", "")
DIR = os.environ.get("PRIVNET_DIR", "")

# Heights: everything active from the chain's start but the rules the checks are about, which come once the
# tripwire outputs exist (coinbase outputs mature after 100 blocks).
MLDSA44, TRIPWIRE, SLHDSA128S, H4T = 120, 130, 140, 160
MARGIN = 6
NODES = {"n1": 18911, "n2": 18921, "n3": 18931}  # RPC port; P2P is one above
SITES = {"A": ("n1", 18501), "B": ("n2", 18502), "C": ("n3", 18503)}
RPC_USER, RPC_PASSWORD = "wallet", "privnet-wallet-rpc"
# Block times: a fixed step from a base before the setup, so that every block is past the median time and none
# is in the future.
STEP = 5


def die(message):
    sys.exit(f"privnet: {message}")


def path(*parts):
    return os.path.join(DIR, *parts)


def network():
    with open(path("network.json")) as f:
        return json.load(f)


def save_network(net):
    with open(path("network.json.tmp"), "w") as f:
        json.dump(net, f, indent=2)
    os.replace(path("network.json.tmp"), path("network.json"))


def node_args(name, net):
    args = [f"-datadir={path(name)}", "-signet", f"-signetchallenge={net['challenge']}", f"-rpcport={NODES[name]}",
            f"-port={NODES[name] + 1}", "-bind=127.0.0.1", f"-rpcuser={RPC_USER}", f"-rpcpassword={RPC_PASSWORD}",
            "-txindex=1", "-txospenderindex=1", "-blockfilterindex=1", "-fallbackfee=0.0002", "-dnsseed=0",
            "-fixedseeds=0", "-listenonion=0", "-debug=net"]
    args += [f"-addnode=127.0.0.1:{NODES[other] + 1}" for other in NODES if other != name]
    if net.get("rules"):
        args += [f"-signetmldsa44={MLDSA44}", f"-signettripwire={TRIPWIRE}@{','.join(net['tripwires'])}",
                 f"-signetslhdsa128s={SLHDSA128S}"]
        if name != "n3":
            args.append(f"-signetlatticetripwire={H4T}@{','.join(net['lattice_tripwires'])}")
    return args


def cli_args(name, net, wallet=None):
    args = [os.path.join(BIN, "bitcoin-cli"), f"-datadir={path(name)}", "-signet", f"-signetchallenge={net['challenge']}",
            f"-rpcport={NODES[name]}", f"-rpcuser={RPC_USER}", f"-rpcpassword={RPC_PASSWORD}"]
    return args + ([f"-rpcwallet={wallet}"] if wallet else [])


def cli(name, *args, wallet=None, net=None, check=True):
    out = subprocess.run(cli_args(name, net or network(), wallet) + [str(a) for a in args], capture_output=True, text=True)
    if check and out.returncode != 0:
        die(f"{name} {' '.join(map(str, args))}: {out.stderr.strip()}")
    text = out.stdout.strip()
    try:
        return json.loads(text)
    except ValueError:
        return text if check else (out.returncode, text or out.stderr.strip())


def start_nodes(net):
    for name in NODES:
        os.makedirs(path(name), exist_ok=True)
        subprocess.run([os.path.join(BIN, "bitcoind")] + node_args(name, net) + ["-daemonwait"], check=True,
                       stdout=subprocess.DEVNULL)
    # -daemonwait returns once a node has started; the wallets of n1 load again with it.
    for wallet in ("funds", "signer", "drill"):
        cli("n1", "loadwallet", wallet, net=net, check=False)


def stop_nodes(net):
    for name in NODES:
        cli(name, "stop", net=net, check=False)
    for name in NODES:
        for _ in range(600):
            if not os.path.exists(path(name, "signet", "bitcoind.pid")):
                break
            time.sleep(0.1)
        else:
            die(f"{name} did not stop")


def site_env(site, net):
    node, port = SITES[site]
    with open(path("rpc-password"), "w") as f:
        f.write(RPC_PASSWORD + "\n")
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG")}
    env.update({"ARK0_RPC_URL": f"http://127.0.0.1:{NODES[node]}/", "ARK0_RPC_USER": RPC_USER,
                "ARK0_RPC_PASSWORD_FILE": path("rpc-password"), "WALLET_LISTEN": f"127.0.0.1:{port}",
                "WALLET_ORIGIN": f"http://127.0.0.1:{port}", "PYTHONPATH": SITE, "PYTHONDONTWRITEBYTECODE": "1",
                # A private network asks far more often than a visitor: no per-visitor limits that matter.
                "RATE_PER_SECOND": "1000", "RATE_BURST": "10000", "FRESH_STATE_PER_SECOND": "1000",
                "FRESH_STATE_BURST": "10000"})
    return env


def start_sites(net):
    for site, (_, port) in SITES.items():
        log = open(path(f"site-{site}.log"), "ab")
        proc = subprocess.Popen([sys.executable, "-I", "-c", f"import sys; sys.path.insert(0, {SITE!r}); "
                                 "from ark0web import wallet; wallet.main()"],
                                env=site_env(site, net), stdout=log, stderr=log, cwd=DIR, start_new_session=True)
        with open(path(f"site-{site}.pid"), "w") as f:
            f.write(str(proc.pid))
    for site, (_, port) in SITES.items():
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/api/state", timeout=5).read()
                break
            except OSError:
                time.sleep(0.2)
        else:
            die(f"site {site} did not answer; see {path(f'site-{site}.log')}")


def stop_sites():
    for site in SITES:
        pid_file = path(f"site-{site}.pid")
        if os.path.exists(pid_file):
            with open(pid_file) as f:
                pid = int(f.read())
            try:
                os.kill(pid, 15)
            except ProcessLookupError:
                pass
            os.remove(pid_file)


def wait_synced(net, height):
    for _ in range(600):
        if all(cli(n, "getblockcount", net=net) == height for n in NODES):
            return
        time.sleep(0.1)
    die(f"the nodes did not reach {height}: " + ", ".join(f"{n} {cli(n, 'getblockcount', net=net)}" for n in NODES))


def mine(count, net=None):
    net = net or network()
    miner = os.path.join(SRC, "contrib", "signet", "miner")
    grind = f"{os.path.join(BIN, 'bitcoin-util')} grind"
    command = " ".join(cli_args("n1", net, "signer"))
    height = cli("n1", "getblockcount", net=net)
    for _ in range(count):
        height += 1
        subprocess.run([sys.executable, miner, f"--cli={command}", "--quiet", "generate", f"--grind-cmd={grind}",
                        f"--address={net['coinbase_address']}", "--min-nbits", f"--set-block-time={net['time_base'] + height * STEP}"],
                       check=True)
    wait_synced(net, height)
    return height


def setup():
    if not all((BIN, SRC, SITE, DIR)):
        die("set PRIVNET_BIN, PRIVNET_SRC, PRIVNET_SITE and PRIVNET_DIR")
    if os.path.exists(path("network.json")):
        die(f"{DIR} has a network already")
    os.makedirs(DIR, exist_ok=True)
    sys.path.insert(0, os.path.join(SRC, "test", "functional"))
    from test_framework.key import ECKey
    from test_framework.wallet_util import bytes_to_wif
    key = ECKey()
    key.generate(True)
    pubkey = key.get_pubkey().get_bytes().hex()
    # The block signing key's challenge, a 1-of-1 multisig as Ark-0's.
    net = {"challenge": f"5121{pubkey}51ae", "signing_key_wif": bytes_to_wif(key.get_bytes(), True),
           "time_base": int(time.time()) - 4 * 3600, "rules": False,
           "heights": {"p2mr": 1, "mldsa44": MLDSA44, "tripwire": TRIPWIRE, "slhdsa128s": SLHDSA128S,
                       "p2mr_lattice_tripwire": H4T}}
    save_network(net)
    # 1. The chain's start, without the rules that need the tripwire outputs.
    start_nodes(net)
    cli("n1", "-named", "createwallet", "wallet_name=signer", "blank=true", net=net)
    desc = f"multi(1,{net['signing_key_wif']})"
    checksum = cli("n1", "getdescriptorinfo", desc, net=net)["checksum"]
    result = cli("n1", "importdescriptors", json.dumps([{"desc": f"{desc}#{checksum}", "timestamp": "now"}]), wallet="signer", net=net)
    if not all(r["success"] for r in result):
        die(f"importdescriptors: {result}")
    for wallet in ("funds", "drill"):
        cli("n1", "-named", "createwallet", f"wallet_name={wallet}", net=net)
    net["coinbase_address"] = cli("n1", "getnewaddress", wallet="funds", net=net)
    save_network(net)
    mine(110, net)
    # 2. The tripwire outputs: two of M3's and three lattice tripwires, all of the drill wallet (any outputs the
    # harness can spend will do); the third lattice tripwire is the drill output.
    outputs = [{cli("n1", "getnewaddress", wallet="drill", net=net): 0.001} for _ in range(5)]
    txid = cli("n1", "-named", "send", f"outputs={json.dumps(outputs)}", "fee_rate=2", wallet="funds", net=net)["txid"]
    tx = cli("n1", "getrawtransaction", txid, 1, net=net)
    by_address = {o["scriptPubKey"]["address"]: o["n"] for o in tx["vout"]}
    vouts = [by_address[list(o)[0]] for o in outputs]
    net["tripwires"] = [f"{txid}:{v}" for v in vouts[:2]]
    net["lattice_tripwires"] = [f"{txid}:{v}" for v in vouts[2:]]
    net["drill"] = net["lattice_tripwires"][2]
    mine(1, net)
    # 3. Every node with the rules (n3 without the lattice tripwire), from heights still ahead.
    stop_nodes(net)
    net["rules"] = True
    save_network(net)
    start_nodes(net)
    for n in NODES:
        for _ in range(100):
            if cli(n, "getconnectioncount", net=net) >= 1:
                break
            time.sleep(0.2)
    start_sites(net)
    write_wallet_configs(net)
    print(json.dumps({"height": cli("n1", "getblockcount", net=net), **{k: net[k] for k in ("challenge", "tripwires", "lattice_tripwires", "drill")}}, indent=2))


def write_wallet_configs(net):
    """The wallet's network files: both M4 sources (A and B), and one with the source that has not upgraded (A and C)."""
    for name, sites in (("wallet-ab.json", "AB"), ("wallet-ac.json", "AC")):
        config = {"api_bases": [f"http://127.0.0.1:{SITES[s][1]}" for s in sites], "signet_challenge": net["challenge"],
                  "heights": net["heights"], "lattice_tripwires": net["lattice_tripwires"],
                  # No ML-DSA-44 block signature on this network: a height above anything it reaches.
                  "pqblock": {"height": 1_000_000, "key": None}}
        with open(path(name), "w") as f:
            json.dump(config, f, indent=2)


def pay(address, amount):
    return cli("n1", "-named", "send", f"outputs={json.dumps([{address: float(amount)}])}", "fee_rate=2", wallet="funds")["txid"]


def drill():
    """Spends the drill lattice tripwire output to the funds wallet."""
    net = network()
    txid, vout = net["drill"].split(":")
    to = cli("n1", "getnewaddress", wallet="funds")
    raw = cli("n1", "createrawtransaction", json.dumps([{"txid": txid, "vout": int(vout)}]), json.dumps([{to: 0.0009}]))
    signed = cli("n1", "signrawtransactionwithwallet", raw, wallet="drill")
    if not signed["complete"]:
        die(f"drill: {signed}")
    return cli("n1", "sendrawtransaction", signed["hex"])


def on_every_node(method, height):
    net = network()
    out = {}
    for n in NODES:
        block = cli(n, "getblockhash", height, net=net)
        cli(n, method, block, net=net)
        out[n] = {"block": block, "tip": cli(n, "getblockcount", net=net)}
    return out


def main():
    if len(sys.argv) < 2:
        die(__doc__)
    command, args = sys.argv[1], sys.argv[2:]
    if command == "setup":
        setup()
    elif command == "start":
        net = network()
        start_nodes(net)
        start_sites(net)
    elif command == "stop":
        stop_sites()
        stop_nodes(network())
    elif command == "mine":
        print(mine(int(args[0])))
    elif command == "pay":
        print(pay(args[0], args[1]))
    elif command == "drill":
        print(drill())
    elif command in ("invalidate", "reconsider"):
        print(json.dumps(on_every_node(command + "block", int(args[0]))))
    elif command == "cli":
        out = cli(args[0], *args[1:], wallet=os.environ.get("PRIVNET_WALLET"))
        print(json.dumps(out, indent=2) if not isinstance(out, str) else out)
    elif command == "info":
        print(json.dumps(network(), indent=2))
    else:
        die(__doc__)


if __name__ == "__main__":
    main()
