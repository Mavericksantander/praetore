----------------------------- MODULE JournalHead -----------------------------
(***************************************************************************)
(* The receipts-journal anchor compared by `praetore-mcp verify            *)
(* --expected-head`. The token is unchained.chained.link.                  *)
(*                                                                         *)
(* link is the hash link after the last chained entry (64 zero bytes when  *)
(* there is no chained entry). unchained is the number of bare evidence    *)
(* lines before the chain. Prepending one of those lines does not change   *)
(* link. It does change unchained, so the token changes. A bare 64-hex     *)
(* link is not this token.                                                 *)
(*                                                                         *)
(* Not model-checked in CI. The Rust test                                   *)
(* prepending_a_valid_unchained_line_fails_verify_with_the_expected_head    *)
(* checks UnchainedPrefixIsInsideTheHead on the real verifier, and         *)
(* journal::tests checks that this invariant is named here.                *)
(***************************************************************************)
EXTENDS Naturals

CONSTANT Max

VARIABLES unchained, chained, link

TypeOK ==
    /\ unchained \in 0..Max
    /\ chained \in 0..Max
    /\ link \in Nat

Head == <<unchained, chained, link>>

(* Prepending one unchained line leaves the chain link as it was. *)
PrependUnchained ==
    /\ unchained < Max
    /\ unchained' = unchained + 1
    /\ UNCHANGED <<chained, link>>

(* The saved head includes unchained, so the new head is a different token. *)
UnchainedPrefixIsInsideTheHead ==
    \A u, c, l \in 0..Max :
        (u < Max) => (<<u + 1, c, l>> # <<u, c, l>>)

=============================================================================
