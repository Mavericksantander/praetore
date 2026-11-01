#!/usr/bin/env python3
"""Checks that index.json attributes each receipt to the agent that signed it.

The agent name appears twice in a bundle: signed inside each receipt
(context.agent, context.profile, the agent identity and, since SAF-14, the
issuer-signed authority constraint praetore.agent_profile) and unsigned in
index.json and in the file name. verify.sh runs this only after
praetore-verify accepted every receipt, so the signed fields read here are
authenticated; this script only compares them with the unsigned copies.

Usage: check-attribution.py <bundle> [index.json]
Exits 0 when every entry agrees with its signed receipt, 1 otherwise.
"""

import collections
import json
import os
import sys

PROFILE_KEY = "praetore.agent_profile"
UNREGISTERED = "unregistered"


def check(bundle, index_path):
    errors = []
    index = json.load(open(index_path))
    evidence_dir = os.path.join(bundle, "evidence")
    on_disk = {"evidence/" + f for f in os.listdir(evidence_dir) if f.endswith(".json")}
    listed = collections.Counter(entry.get("file") for entry in index)
    for name in sorted(on_disk | set(listed), key=str):
        if listed[name] != 1 or name not in on_disk:
            errors.append(f"{name}: {listed[name]} entradas en index.json, en disco: {name in on_disk}")

    ids = collections.defaultdict(set)
    profiles = collections.defaultdict(set)
    issuer_bound = collections.Counter()
    tally = collections.Counter()
    for entry in index:
        name = entry.get("file")
        if name not in on_disk:
            continue
        evidence = json.load(open(os.path.join(bundle, name)))
        context = evidence.get("context", {})
        agent = context.get("agent")
        if not isinstance(agent, str):
            errors.append(f"{name}: el recibo no firma el nombre del agente")
            continue
        # Receipts from before context.profile (set 04): the profile is the agent.
        profile = context.get("profile", agent)
        agent_id = evidence["agent"]["id"]
        if profile != UNREGISTERED and profile != agent:
            errors.append(f"{name}: agente firmado {agent!r} y perfil firmado {profile!r} difieren")
        if entry.get("agent") != agent:
            errors.append(f"{name}: index.json dice agent={entry.get('agent')!r}, el recibo firmado dice {agent!r}")
        if entry.get("profile") is not None and entry["profile"] != profile:
            errors.append(f"{name}: index.json dice profile={entry['profile']!r}, el recibo firmado dice {profile!r}")
        if "agent_id" in entry and entry["agent_id"] != agent_id:
            errors.append(f"{name}: index.json dice agent_id={entry['agent_id']!r}, el recibo firmado dice {agent_id!r}")
        constraints = {c["key"]: c["value"] for c in evidence["authority"]["constraints"]}
        if PROFILE_KEY in constraints:
            requested = evidence["action"]["parameters"].get(PROFILE_KEY)
            if constraints[PROFILE_KEY] != profile or requested != profile:
                errors.append(f"{name}: autoridad emitida para {constraints[PROFILE_KEY]!r}, recibo de {profile!r}")
            issuer_bound[profile] += 1
        ids[profile].add(agent_id)
        profiles[agent_id].add(profile)
        tally[(agent, evidence["decision"]["outcome"])] += 1

    # A bundle comes from one `init`: one identity per profile and vice versa.
    for profile, found in sorted(ids.items()):
        if len(found) != 1:
            errors.append(f"perfil {profile!r} firmado por {len(found)} identidades")
    for agent_id, found in sorted(profiles.items()):
        if len(found) != 1:
            errors.append(f"identidad {agent_id} firma como {sorted(found)}")
    return errors, tally, ids, issuer_bound


def main():
    if len(sys.argv) not in (2, 3):
        print(__doc__.strip().splitlines()[-2], file=sys.stderr)
        return 2
    bundle = sys.argv[1]
    index_path = sys.argv[2] if len(sys.argv) == 3 else os.path.join(bundle, "index.json")
    errors, tally, ids, issuer_bound = check(bundle, index_path)
    for error in errors:
        print("FALLO:", error)
    if errors:
        return 1
    for (agent, outcome), count in sorted(tally.items()):
        print(f"{agent:<16} {outcome:<16} {count}")
    for profile, found in sorted(ids.items()):
        bound = "emisor, agente y atestador" if issuer_bound[profile] else "agente y atestador"
        print(f"perfil {profile:<12} agent id {next(iter(found))}  (nombre del perfil firmado por: {bound})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
