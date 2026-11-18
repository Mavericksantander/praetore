--------------------------- MODULE ApprovalWindow ---------------------------
(***************************************************************************)
(* The signed approval window (crates/praetore-mcp/src/approvals.rs).     *)
(*                                                                         *)
(* ApprovalWindow is built from the retained receipt's signed timestamp   *)
(* and the TTL. A new decision copies that timestamp exactly. A 0.3.6     *)
(* decision stores it truncated to a whole second: the skew is less than  *)
(* one second (Second below). expires_at - created_at is the TTL, and     *)
(* that span is at most MaxTtl seconds either way. Timestamps in this     *)
(* model are milliseconds.                                                 *)
(*                                                                         *)
(* The Rust test decide_refuses_a_pending_file_edited_to_2099 edits a     *)
(* pending file to 2099 and checks that decide signs nothing.             *)
(* verify_rejects_a_signed_window_longer_than_a_day signs a fixture whose *)
(* span is MaxTtl + 1 and checks that `verify` exits 1.                   *)
(***************************************************************************)
EXTENDS Integers

CONSTANTS MaxTtl

Second == 1000

VARIABLES held_timestamp, ttl, created_at, expires_at, signed

vars == <<held_timestamp, ttl, created_at, expires_at, signed>>

whole_second(t) == t - (t % Second)

Init ==
    /\ held_timestamp \in 0 .. (10 * Second)
    /\ ttl \in 1..MaxTtl
    /\ created_at = 0
    /\ expires_at = 0
    /\ signed = FALSE

\* New decision: created_at is the receipt timestamp.
Sign ==
    /\ ~signed
    /\ created_at' = held_timestamp
    /\ expires_at' = held_timestamp + (ttl * Second)
    /\ signed' = TRUE
    /\ UNCHANGED <<held_timestamp, ttl>>

\* 0.3.6 decision: created_at is that timestamp truncated to a whole second.
\* The skew is less than one second. The TTL bound is the same.
Historical ==
    /\ ~signed
    /\ held_timestamp # whole_second(held_timestamp)
    /\ created_at' = whole_second(held_timestamp)
    /\ held_timestamp - created_at' < Second
    /\ expires_at' = created_at' + (ttl * Second)
    /\ signed' = TRUE
    /\ UNCHANGED <<held_timestamp, ttl>>

Next == Sign \/ Historical

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ held_timestamp \in 0 .. (10 * Second)
    /\ ttl \in 1..MaxTtl
    /\ created_at \in Int
    /\ expires_at \in Int
    /\ signed \in BOOLEAN

(* Exact for a new decision. Whole-second truncation, skew < 1s, for a
   0.3.6 decision. The span is the TTL and is at most MaxTtl seconds. *)
DecisionWindowWithinSignedHoldPlusTtl ==
    signed =>
        /\ expires_at - created_at = ttl * Second
        /\ expires_at - created_at <= MaxTtl * Second
        /\ \/ created_at = held_timestamp
           \/ /\ created_at = whole_second(held_timestamp)
              /\ held_timestamp - created_at < Second
              /\ held_timestamp >= created_at

=============================================================================
