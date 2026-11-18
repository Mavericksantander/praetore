---------------------------- MODULE JournalVerify ----------------------------
(***************************************************************************)
(* What `praetore-mcp verify` claims, next to JournalAppend.tla.           *)
(*                                                                         *)
(* `saved` is the line sequence whose head was kept off the machine.       *)
(* `lines` is the sequence `verify` reads. An extension is `saved` with    *)
(* lines only added at the end. Anything else is a non-append change: a    *)
(* deletion, a duplication or a reordering, including one whose hash links *)
(* were recomputed afterwards. Those links are not signed.                 *)
(*                                                                         *)
(* Not model-checked in CI. The Rust test                                   *)
(* rechained_middle_deletion_is_unanchored_and_fails_the_saved_heads        *)
(* checks both invariants on the real verifier.                            *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANT MaxLen

VARIABLES saved, lines, anchored, claimed

TypeOK ==
    /\ saved \in Seq(1..MaxLen)
    /\ lines \in Seq(1..MaxLen)
    /\ anchored \in BOOLEAN
    /\ claimed \in {"anchored", "unanchored", "fail"}

IsExtension(prefix, longer) ==
    /\ Len(longer) >= Len(prefix)
    /\ \A i \in 1..Len(prefix) : longer[i] = prefix[i]

(* With a saved head, a sequence that is not that journal plus a suffix   *)
(* must not be accepted.                                                    *)
AnchoredVerifyDetectsAnyNonAppendChange ==
    (anchored /\ ~IsExtension(saved, lines)) => claimed = "fail"

(* A run that was not given a saved head must not say it was anchored.     *)
UnanchoredNeverClaimsAnchored ==
    ~anchored => claimed # "anchored"

=============================================================================
