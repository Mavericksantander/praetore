# Limitations and responsible use / Limitaciones y uso responsable

PRÆTORE provides deterministic authorization and governance primitives for
AI-enabled systems. This page says what those primitives do not
do, and how to use them without overstating what they show. It is a summary:
the [README](../README.md#limitations) and the
[threat model](threat-model.md#guarantees-and-non-guarantees) have the details.

## Limitations

Readiness for real deployments has not been established. PRÆTORE is under
active development and has not been independently audited or accredited.

**What is decided.**

- PRÆTORE evaluates a declared action against a policy and a delegated
  authority. It does not evaluate a model, a prompt or the quality of a model's
  output, and it does not decide whether a policy is appropriate. An `allowed`
  answer means that the policy allowed the action, not that the action was a
  good idea.
- Enforcement is cooperative. PRÆTORE governs only the actions submitted to it.
  It cannot stop an agent or another process from acting directly, so a
  deployment has to place a mandatory enforcement point in front of each
  protected tool.
- PRÆTORE is not a sandbox by itself. An end-to-end sandbox has not been
  validated in a target cluster.
- Path checks in core are local and lexical. The check in `praetore-mcp` is
  point-in-time, so a path can change after it.

**What is recorded.**

- A receipt verified against a pinned attester key shows that the holder of
  that key recorded a decision. It does not show that the key or the host were
  not compromised, or that the decision was right, and it does not independently confirm that the
  action ran: `executed` and `confirmed` record what the dispatcher adapter
  reported.
- A third party cannot prove that no receipt was deleted from the journal.
  Nothing signs or publishes the journal's sequence or head. External anchoring
  of the head is only a proposal, and an anchor would cover only up to that
  head.
- Safety actions are outside the authorization path. The executor of an
  AI-enabled system runs them without waiting for PRÆTORE, which can only
  record them afterwards. That record does not approve or stop anything, and
  it does not show that every action was reported: an executor can stay silent,
  and an event the client drops is visible only as a gap once a later event of
  that source arrives, so the last events before a source stops are invisible.
  Messages dropped inside the ingester appear as signed counts.

**What has been tested.**

- CI fuzzes in bounded runs only. A clean run does not prove the absence of
  bugs.
- Not every flow has been exercised on every platform; see
  [Not verified](../README.md#not-verified).
- Passing CI is not an assessment of a deployment, and earlier reviews did not
  cover the current candidate or deployment-specific adapters. Trust anchors,
  key custody, the time source, replay storage, host hardening and the atomic
  relationship between authorization and action execution remain the
  deployment's responsibility.

## Responsible use

- **Do not make PRÆTORE the only control over a high-consequence decision.**
  Close the applicable [pre-user deployment gates](pre-user-pilot-gates.md),
  with named owners, before relying on it for one.
- **Keep failsafes independent.** A safety action must not depend on PRÆTORE
  being available.
- **Keep people accountable.** `RequireApproval` is only as meaningful as the
  review behind it: approvers need to see what they approve, and enough time to
  refuse it. Do not present an action as reviewed by a person if it was not.
- **Grant the least authority that works**, for the shortest time that works,
  and start from a deny-by-default policy.
- **Describe the evidence accurately.** Do not present a receipt, a verifier
  result or this project's documents as a statement that an AI-enabled system
  is correct, compliant or free of risk.
- **Check what applies to you.** Laws and duties on AI, on automated
  decisions and on the data in a journal depend on the deployment; PRÆTORE does
  not determine or meet them for you.

## Reporting a concern

To report a concern about the use of AI, see
[SECURITY.md](../SECURITY.md#concerns-about-the-use-of-ai).
