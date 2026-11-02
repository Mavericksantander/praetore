#!/usr/bin/env python3
"""Checks that index.json attributes each receipt to the agent that signed it.

The agent name appears twice in a bundle: signed inside each receipt
(context.agent, context.profile, the agent identity and, since SAF-14, the
issuer-signed authority constraint praetore.agent_profile) and unsigned in
index.json and in the file name. verify.sh runs this only after
praetore-verify accepted every receipt, so the signed fields read here are
authenticated; this script only compares them with the unsigned copies. Both
accept only regular, non-hidden *.json files in evidence/ and fail on any
other entry, and verify.sh runs both on one copy of the bundle, so they read
the same bytes. A receipt that appears twice (same evidence_id, or same
agent id and request_id) fails: the counts are one per decision.

A denial the hook's own guard decided (GHSA-wg33-3h8v-xvqw) is signed as
`unregistered` and names, in the signed context, the guard
(praetore.hook_guard) and the profile the call would otherwise have had
(praetore.requested_profile). Those fields must come together, name a known
guard and a profile other than main and unregistered that equals the signed
agent, and belong to a Deny.

Usage: check-attribution.py <bundle> [index.json]
Exits 0 when every entry agrees with its signed receipt, 1 otherwise.
"""

import collections
import json
import os
import sys

PROFILE_KEY = "praetore.agent_profile"
UNREGISTERED = "unregistered"
GUARD_KEY = "praetore.hook_guard"
REQUESTED_KEY = "praetore.requested_profile"
GUARDS = {
    "exec_reserved_to_main",
    "client_config_write",
    "governance_write",
    "path_check_failed",
    "no_project_root",
}


def check(bundle, index_path):
    errors = []
    index = json.load(open(index_path))
    evidence_dir = os.path.join(bundle, "evidence")
    # Same rule as step 3 of verify.sh, so this reads exactly the receipts
    # praetore-verify checked: only regular, non-hidden *.json files. Any
    # other entry (hidden file, directory, symlink, other name) fails.
    on_disk = set()
    with os.scandir(evidence_dir) as entries:
        for entry in entries:
            if (
                entry.name.startswith(".")
                or not entry.name.endswith(".json")
                or entry.is_symlink()
                or not entry.is_file(follow_symlinks=False)
            ):
                errors.append(f"evidence/{entry.name}: entrada no permitida (solo archivos regulares *.json no ocultos)")
            else:
                on_disk.add("evidence/" + entry.name)
    listed = collections.Counter(entry.get("file") for entry in index)
    for name in sorted(on_disk | set(listed), key=str):
        if listed[name] != 1 or name not in on_disk:
            errors.append(f"{name}: {listed[name]} entradas en index.json, en disco: {name in on_disk}")

    ids = collections.defaultdict(set)
    profiles = collections.defaultdict(set)
    issuer_bound = collections.Counter()
    tally = collections.Counter()
    # One decision per receipt: the same evidence_id, or the same request
    # (agent id, request_id), twice in a bundle (copies under other names,
    # hard links) would count one decision several times.
    seen_evidence = {}
    seen_request = {}
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
        for seen, key, what in (
            (seen_evidence, evidence["evidence_id"], "evidence_id"),
            (seen_request, (agent_id, evidence["request_id"]), "(agent id, request_id)"),
        ):
            if key in seen:
                errors.append(f"{name}: {what} repetido, ya está en {seen[key]}")
            else:
                seen[key] = name
        guard, requested = context.get(GUARD_KEY), context.get(REQUESTED_KEY)
        if guard is not None or requested is not None:
            if guard not in GUARDS:
                errors.append(f"{name}: guard firmado desconocido {guard!r}")
            if not isinstance(requested, str) or requested in ("main", UNREGISTERED) or requested != agent:
                errors.append(f"{name}: perfil pedido {requested!r} no corresponde al agente firmado {agent!r}")
            if profile != UNREGISTERED or evidence["decision"]["outcome"] != "Deny":
                errors.append(f"{name}: un guard del hook solo firma un Deny como {UNREGISTERED!r}")
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
        # Any agent_type outside a registered profile is shown escaped to
        # ASCII under unregistered, so "coder " or a Cyrillic "о" cannot be
        # read as the coder profile.
        label = f"unregistered(agent_type={json.dumps(agent)})" if profile == UNREGISTERED else profile
        if guard in GUARDS:
            label = f"unregistered(agent_type={json.dumps(agent)}, guard={guard})"
        tally[(label, evidence["decision"]["outcome"])] += 1

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
