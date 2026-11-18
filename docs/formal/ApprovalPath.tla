---------------------------- MODULE ApprovalPath ----------------------------
(***************************************************************************)
(* Consuming a local approval (crates/praetore-mcp/src/approvals.rs).     *)
(*                                                                         *)
(* Binding carries the path_check of the retained receipt. An approval is *)
(* consumed only when the path_check of the call being evaluated is       *)
(* identical and every status is "same".                                   *)
(*                                                                         *)
(* The Rust test                                                           *)
(* a_symlink_in_place_of_the_held_directory_does_not_consume_the_approval  *)
(* holds a call against a real directory, replaces that directory with a  *)
(* symlink, evaluates again, and checks the result is a hold with the     *)
(* approval still unused.                                                  *)
(***************************************************************************)
EXTENDS FiniteSets

VARIABLES held_check, current_check, consumed

vars == <<held_check, current_check, consumed>>

Status == {"same", "differs", "unresolved", "ambiguous"}

Init ==
    /\ held_check \in Status
    /\ current_check \in Status
    /\ consumed = FALSE

\* Consume only when both checks are the same value and that value is same.
Consume ==
    /\ ~consumed
    /\ current_check = held_check
    /\ current_check = "same"
    /\ consumed' = TRUE
    /\ UNCHANGED <<held_check, current_check>>

Next == Consume

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ held_check \in Status
    /\ current_check \in Status
    /\ consumed \in BOOLEAN

(* A consumed approval saw the same path check as the one that was held,
   and that check was same. *)
ConsumedApprovalPathCheckEqualsHeld ==
    consumed =>
        /\ current_check = held_check
        /\ current_check = "same"

=============================================================================
