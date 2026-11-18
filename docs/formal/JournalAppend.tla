---------------------------- MODULE JournalAppend ----------------------------
(***************************************************************************)
(* One call of journal_io::commit_journal_line (crates/praetore-mcp), the  *)
(* append shared by the receipts journal and the approval journal.         *)
(*                                                                         *)
(* The line is written with one write, which stores n bytes (0 to          *)
(* LineLen) and returns a count or an error. A whole line is fsynced; an   *)
(* fsync error is returned and nothing is truncated. A short or failed     *)
(* write is rolled back: set_len to the length from before the call, then  *)
(* fsync of that truncation. If the rollback itself fails, the error says  *)
(* so and the length is not known.                                         *)
(*                                                                         *)
(* The Rust test journal_io::tests::append_error_preserves_length checks   *)
(* AppendErrorPreservesLength on the real function, for every fault mode   *)
(* and every stored prefix of a 401-byte line.                             *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS LineLen, MaxLen

VARIABLES before, file_len, write_result, rollback_result, returned

vars == <<before, file_len, write_result, rollback_result, returned>>

Init ==
    /\ before \in 0..MaxLen
    /\ file_len = before
    /\ write_result = "none"
    /\ rollback_result = "none"
    /\ returned = "none"

Write ==
    /\ write_result = "none"
    /\ \E n \in 0..LineLen, err \in BOOLEAN :
         /\ file_len' = before + n
         /\ write_result' = IF n = LineLen /\ ~err THEN "ok"
                            ELSE IF err THEN "error" ELSE "short"
    /\ UNCHANGED <<before, rollback_result, returned>>

Sync ==
    /\ write_result = "ok"
    /\ returned = "none"
    /\ returned' \in {"ok", "error"}
    /\ UNCHANGED <<before, file_len, write_result, rollback_result>>

Rollback ==
    /\ write_result \in {"short", "error"}
    /\ rollback_result = "none"
    /\ \/ /\ rollback_result' = "ok"
          /\ file_len' = before
       \/ /\ rollback_result' = "fail"
          /\ file_len' \in {before, file_len}
    /\ returned' = "error"
    /\ UNCHANGED <<before, write_result>>

Next == Write \/ Sync \/ Rollback

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ before \in 0..MaxLen
    /\ file_len \in 0..(MaxLen + LineLen)
    /\ write_result \in {"none", "ok", "short", "error"}
    /\ rollback_result \in {"none", "ok", "fail"}
    /\ returned \in {"none", "ok", "error"}

(* The append returned an error because the write was short or failed,    *)
(* and the rollback succeeded: the file has the length it had before.     *)
AppendErrorPreservesLength ==
    (write_result \in {"short", "error"} /\ rollback_result = "ok")
        => file_len = before

(* Ok is returned only for a whole line.                                  *)
OkMeansWholeLine ==
    returned = "ok" => file_len = before + LineLen

=============================================================================
