------------------------------ MODULE KeyPath ------------------------------
(***************************************************************************)
(* Opening one local key file (crates/praetore-mcp/src/keys.rs).          *)
(*                                                                         *)
(* KeyPath is built only after lstat of the keys directory and of the     *)
(* named file. Neither may be a symlink. Both are owned by the effective  *)
(* uid. The file is then opened with O_NOFOLLOW and read from that        *)
(* descriptor. A symlink at either name stays closed: source stays        *)
(* "none".                                                                 *)
(*                                                                         *)
(* The Rust tests in crates/praetore-mcp/tests/key_path.rs run this on a  *)
(* keys directory that is a symlink and, separately, on a key file that   *)
(* is a symlink.                                                           *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS Euid

VARIABLES dir_kind, dir_owner, file_kind, file_owner, opened, source

vars == <<dir_kind, dir_owner, file_kind, file_owner, opened, source>>

Kind == {"directory", "file", "symlink", "other"}
Owner == {Euid, "other"}

Init ==
    /\ dir_kind \in Kind
    /\ dir_owner \in Owner
    /\ file_kind \in Kind
    /\ file_owner \in Owner
    /\ opened = "none"
    /\ source = "none"

\* lstat both names, then open the file with O_NOFOLLOW and read that fd.
Open ==
    /\ opened = "none"
    /\ IF dir_kind = "directory" /\ dir_owner = Euid
          /\ file_kind = "file" /\ file_owner = Euid
       THEN /\ opened' = "fd"
            /\ source' = "fd"
       ELSE /\ opened' = "refused"
            /\ source' = "none"
    /\ UNCHANGED <<dir_kind, dir_owner, file_kind, file_owner>>

Next == Open

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ dir_kind \in Kind
    /\ dir_owner \in Owner
    /\ file_kind \in Kind
    /\ file_owner \in Owner
    /\ opened \in {"none", "fd", "refused"}
    /\ source \in {"none", "fd"}

(* A key is read only from a descriptor opened on a regular file in a
   directory, both owned by the effective uid, neither a symlink. *)
KeysReadOnlyFromOwnedNonSymlink ==
    source = "fd" =>
        /\ dir_kind = "directory"
        /\ dir_owner = Euid
        /\ file_kind = "file"
        /\ file_owner = Euid
        /\ opened = "fd"

=============================================================================
