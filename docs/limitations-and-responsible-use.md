# Limitations and responsible use / Limitaciones y uso responsable

PRÆTORE provides deterministic authorization and governance primitives for
autonomous and AI-enabled systems. This page says what those primitives do not
do, and how to use them without overstating what they show. It is a summary:
the [README](../README.md#limitations) and the
[threat model](threat-model.md#guarantees-and-non-guarantees) have the details.

## Limitations

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

- A receipt shows that a decision was recorded and signed. It does not show
  that the decision was right, and it does not independently confirm that the
  action ran: `executed` and `confirmed` record what the dispatcher adapter
  reported.
- A third party cannot prove that no receipt was deleted from the journal
  unless the journal's head was anchored outside the producer's control.
- Safety actions are outside the authorization path. The executor of an
  AI-enabled system runs them without waiting for PRÆTORE, which can only
  record them afterwards. That record does not approve or stop anything, and
  under a flood messages can be dropped: they then show up as signed counts or
  sequence gaps, not as individual records.

**What has been tested.**

- CI fuzzes in bounded runs only. A clean run does not prove the absence of
  bugs.
- Not every flow has been exercised on every platform; see
  [Not verified](../README.md#not-verified).
- Passing CI or a past review is not an assessment of a deployment. Trust
  anchors, key custody, the time source, replay storage and host hardening
  remain the deployment's responsibility.

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
- **Tell people what applies to them.** Laws and duties on AI, on automated
  decisions and on the data in a journal depend on the deployment; PRÆTORE does
  not determine or meet them for you.

## Reporting a concern

To report a concern about the use of AI, see
[SECURITY.md](../SECURITY.md#concerns-about-the-use-of-ai).
