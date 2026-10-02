#!/usr/bin/env python3
"""Build the fixed topology of an Enclave localnet (nym-sdk's NymTopology
JSON) from the nodes' own HTTP APIs.

    topology.py OUT.json mix=IP:MIXPORT:HTTPPORT ... gateway=IP:MIXPORT:HTTPPORT:WSPORT

Mix nodes go to layers 1, 2, 3 in the order given; gateways are entry and
exit. Waits for every node's /api/v1/host-information. The key rotation id
is 0 ("unknown"), so nodes try their primary and then their secondary
sphinx key, whatever rotation they are on.
"""
import json
import sys
import time
import urllib.request

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s):
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    out = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\0" * pad + out


def host_information(ip, port):
    url = f"http://{ip}:{port}/api/v1/host-information"
    deadline = time.time() + 300
    while True:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                return json.load(r)
        except Exception as e:  # not up yet
            if time.time() > deadline:
                raise SystemExit(f"{url}: {e}")
            time.sleep(2)


def keys(info):
    data = info.get("data", info)
    k = data["keys"]
    identity = k["ed25519_identity"]
    sphinx = k.get("primary_x25519_sphinx_key") or k.get("x25519_sphinx")
    if isinstance(sphinx, dict):
        sphinx = sphinx["public_key"]
    i, s = b58decode(identity), b58decode(sphinx)
    assert len(i) == 32 and len(s) == 32, (identity, sphinx)
    return list(i), list(s)


def main(argv):
    out, specs = argv[0], argv[1:]
    nodes, mixes, gateways = {}, [], []
    for node_id, spec in enumerate(specs, start=1):
        role, addr = spec.split("=", 1)
        parts = addr.split(":")
        ip, mix_port, http_port = parts[0], int(parts[1]), int(parts[2])
        identity, sphinx = keys(host_information(ip, http_port))
        node = {
            "node_id": node_id,
            "mix_host": f"{ip}:{mix_port}",
            "entry": None,
            "identity_key": identity,
            "sphinx_key": sphinx,
            "supported_roles": {"mixnode": True, "mixnet_entry": False, "mixnet_exit": False},
        }
        if role == "gateway":
            node["entry"] = {
                "ip_addresses": [ip],
                "clients_ws_port": int(parts[3]),
                "hostname": None,
                "clients_wss_port": None,
            }
            node["supported_roles"] = {"mixnode": False, "mixnet_entry": True, "mixnet_exit": True}
            gateways.append(node_id)
        else:
            mixes.append(node_id)
        nodes[str(node_id)] = node
    if len(mixes) < 3 or not gateways:
        raise SystemExit("need three mix nodes and a gateway")
    layers = {f"layer{i + 1}": mixes[i::3] for i in range(3)}
    topology = {
        "metadata": {
            "key_rotation_id": 0,
            "absolute_epoch_id": 0,
            "refreshed_at": "2026-01-01T00:00:00Z",
        },
        "rewarded_set": {
            "epoch_id": 0,
            "entry_gateways": gateways,
            "exit_gateways": gateways,
            **layers,
            "standby": [],
        },
        "node_details": nodes,
    }
    with open(out, "w") as f:
        json.dump(topology, f, indent=1)
    print(f"{out}: {len(mixes)} mix nodes, {len(gateways)} gateway(s)")


if __name__ == "__main__":
    main(sys.argv[1:])
