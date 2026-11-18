----------------------- MODULE EvaluatedEqualsExecuted -----------------------
(***************************************************************************)
(* Client JSON numbers that the proxy evaluates and may forward.           *)
(*                                                                         *)
(* A tools/call line is forwarded only when every number literal on it is  *)
(* canonical: its text equals the canonical serialization of a correct     *)
(* parse (binary64 round-to-nearest-even, or an integer in [-2^53, 2^53]). *)
(* Otherwise the line is Ambiguous and enforce does not forward it.        *)
(* The rules for integers, exponents and trailing zeros are in             *)
(* crates/praetore-mcp/src/json.rs.                                        *)
(*                                                                         *)
(* For every forwarded call the value the policy compared is the value a   *)
(* correct parser produces from the bytes the server receives:             *)
(*                                                                         *)
(*   EvaluatedValue = ExecutedValue                                        *)
(***************************************************************************)

CONSTANTS Calls

VARIABLES evaluated, executed, forwarded

vars == <<evaluated, executed, forwarded>>

TypeOK ==
    /\ evaluated \in [Calls -> STRING]
    /\ executed \in [Calls -> STRING]
    /\ forwarded \in [Calls -> BOOLEAN]

(* The proxy refuses a call whose literal is not canonical, and it never   *)
(* forwards a call whose evaluated value differs from the executed value.  *)
EvaluatedValueEqualsExecutedValue ==
    \A c \in Calls : forwarded[c] => evaluated[c] = executed[c]

=============================================================================
