--------------------------- MODULE ApprovalWindow ---------------------------
(***************************************************************************)
(* The signed approval window (crates/praetore-mcp/src/approvals.rs).     *)
(*                                                                         *)
(* ApprovalWindow is built from the retained receipt's signed timestamp   *)
(* and the TTL. created_at is that timestamp. expires_at - created_at is  *)
(* the TTL, and that span is at most MaxTtl seconds. The pending file's   *)
(* created_at and expires_at are not the source of the signed window.     *)
(*                                                                         *)
(* The Rust test decide_refuses_a_pending_file_edited_to_2099 edits a     *)
(* pending file to 2099 and checks that decide signs nothing.             *)
(* verify_rejects_a_signed_window_longer_than_a_day signs a fixture whose *)
(* span is MaxTtl + 1 and checks that `verify` exits 1.                   *)
(***************************************************************************)
EXTENDS Integers

CONSTANTS MaxTtl

VARIABLES held_timestamp, ttl, created_at, expires_at, signed

vars == <<held_timestamp, ttl, created_at, expires_at, signed>>

Init ==
    /\ held_timestamp \in Int
    /\ ttl \in 1..MaxTtl
    /\ created_at = 0
    /\ expires_at = 0
    /\ signed = FALSE

Sign ==
    /\ ~signed
    /\ created_at' = held_timestamp
    /\ expires_at' = held_timestamp + ttl
    /\ signed' = TRUE
    /\ UNCHANGED <<held_timestamp, ttl>>

Next == Sign

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ held_timestamp \in Int
    /\ ttl \in 1..MaxTtl
    /\ created_at \in Int
    /\ expires_at \in Int
    /\ signed \in BOOLEAN

(* A signed window starts at the retained receipt and is at most MaxTtl. *)
DecisionWindowWithinSignedHoldPlusTtl ==
    signed =>
        /\ created_at = held_timestamp
        /\ expires_at = created_at + ttl
        /\ expires_at - created_at <= MaxTtl

=============================================================================
