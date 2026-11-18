------------------------- MODULE JournalVerifiedWrite -------------------------
(***************************************************************************)
(* The receipts writer in crates/praetore-mcp. A line is written only      *)
(* after VerifiedLine::seal has parsed that exact line                     *)
(* (parse_line(chained_line(pos, json))), checked verify_integrity and     *)
(* computed the next link. Journal::append accepts only that value.        *)
(* The approval journal seals the same way: the line is re-parsed and the  *)
(* next link is computed before append_journal_file.                       *)
(*                                                                         *)
(* JournalAlwaysVerifies: every prefix of the journal that this writer     *)
(* has successfully appended passes verify.                                 *)
(*                                                                         *)
(* NoExecutionWithoutEvidence: in enforce and in observe, a call whose     *)
(* receipt line does not seal is not forwarded. Nothing is written for it. *)
(* A later call can still be sealed, written and forwarded.                *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANT Max

ASSUME Max \in Nat /\ Max >= 1

VARIABLES
    journal,   \* sequence of sealed lines, each the token "ok"
    phase,     \* idle, considered, written, forwarded, refused
    mode,      \* "enforce" or "observe"
    seal_ok    \* the candidate line re-parsed and verified

vars == <<journal, phase, mode, seal_ok>>

Init ==
    /\ journal = <<>>
    /\ phase = "idle"
    /\ mode \in {"enforce", "observe"}
    /\ seal_ok \in BOOLEAN

TypeOK ==
    /\ journal \in Seq({"ok"})
    /\ Len(journal) <= Max
    /\ phase \in {"idle", "considered", "written", "forwarded", "refused"}
    /\ mode \in {"enforce", "observe"}
    /\ seal_ok \in BOOLEAN

\* Pick the next candidate. Nothing is written here.
Consider ==
    /\ phase \in {"idle", "forwarded", "refused"}
    /\ Len(journal) < Max
    /\ seal_ok' \in BOOLEAN
    /\ phase' = "considered"
    /\ UNCHANGED <<journal, mode>>

\* Append only a sealed line. The bytes on disk are the bytes that verified.
Append ==
    /\ phase = "considered"
    /\ seal_ok
    /\ journal' = Append(journal, "ok")
    /\ phase' = "written"
    /\ UNCHANGED <<mode, seal_ok>>

\* Forward only after that sealed line was written. Same rule in both modes.
Forward ==
    /\ phase = "written"
    /\ mode \in {"enforce", "observe"}
    /\ phase' = "forwarded"
    /\ UNCHANGED <<journal, mode, seal_ok>>

\* The line did not seal. It is not written and the call is not forwarded.
Refuse ==
    /\ phase = "considered"
    /\ ~seal_ok
    /\ phase' = "refused"
    /\ UNCHANGED <<journal, mode, seal_ok>>

Next == Consider \/ Append \/ Forward \/ Refuse

Spec == Init /\ [][Next]_vars

\* Every written prefix is a sequence of sealed lines, which verify accepts.
JournalAlwaysVerifies ==
    \A n \in 0..Len(journal) :
        \A i \in 1..n : SubSeq(journal, 1, n)[i] = "ok"

\* A forwarded call had a sealed line, in enforce and in observe.
NoExecutionWithoutEvidence ==
    phase = "forwarded" =>
        /\ seal_ok
        /\ mode \in {"enforce", "observe"}
        /\ journal # <<>>
        /\ journal[Len(journal)] = "ok"

\* A refusal wrote nothing for that candidate.
RefusedWritesNothing ==
    phase = "refused" => ~seal_ok

=============================================================================
