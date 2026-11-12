-- Attestation INSERT compares output_digest with the journal row (0021
-- compared the signed identity and action_digest, and not the output).
--
-- A NULL output_json matches a null or absent output_digest. Any other
-- output_json matches the lowercase hex SHA-256 of the UTF-8 bytes of the
-- label PRAETORE_EXECUTION_OUTPUT_V1, a NUL byte, and output_json itself.
-- The text is hashed as stored: output_json is text because an output may
-- carry escapes PostgreSQL's JSON types refuse, and the gateway stores the
-- canonical JSON of the output, which is the text whose digest it signs.
--
-- Rows already written are not checked or rewritten. Forward-only;
-- 0001-0022 are not edited. The previous insert function stays so the
-- rollback can put its trigger back. Every new object has a new name.
-- Manual rollback: docs/rollback/0023-attestation-output-digest.sql.
-- Applied inside the runner's transaction.

CREATE FUNCTION praetore.execution_output_digest_v1(output_json text)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog, praetore, pg_temp
AS $output_digest$
DECLARE
    mask CONSTANT bigint := 4294967295;
    k bigint[] := ARRAY[
        x'428a2f98'::bigint, x'71374491'::bigint, x'b5c0fbcf'::bigint, x'e9b5dba5'::bigint,
        x'3956c25b'::bigint, x'59f111f1'::bigint, x'923f82a4'::bigint, x'ab1c5ed5'::bigint,
        x'd807aa98'::bigint, x'12835b01'::bigint, x'243185be'::bigint, x'550c7dc3'::bigint,
        x'72be5d74'::bigint, x'80deb1fe'::bigint, x'9bdc06a7'::bigint, x'c19bf174'::bigint,
        x'e49b69c1'::bigint, x'efbe4786'::bigint, x'0fc19dc6'::bigint, x'240ca1cc'::bigint,
        x'2de92c6f'::bigint, x'4a7484aa'::bigint, x'5cb0a9dc'::bigint, x'76f988da'::bigint,
        x'983e5152'::bigint, x'a831c66d'::bigint, x'b00327c8'::bigint, x'bf597fc7'::bigint,
        x'c6e00bf3'::bigint, x'd5a79147'::bigint, x'06ca6351'::bigint, x'14292967'::bigint,
        x'27b70a85'::bigint, x'2e1b2138'::bigint, x'4d2c6dfc'::bigint, x'53380d13'::bigint,
        x'650a7354'::bigint, x'766a0abb'::bigint, x'81c2c92e'::bigint, x'92722c85'::bigint,
        x'a2bfe8a1'::bigint, x'a81a664b'::bigint, x'c24b8b70'::bigint, x'c76c51a3'::bigint,
        x'd192e819'::bigint, x'd6990624'::bigint, x'f40e3585'::bigint, x'106aa070'::bigint,
        x'19a4c116'::bigint, x'1e376c08'::bigint, x'2748774c'::bigint, x'34b0bcb5'::bigint,
        x'391c0cb3'::bigint, x'4ed8aa4a'::bigint, x'5b9cca4f'::bigint, x'682e6ff3'::bigint,
        x'748f82ee'::bigint, x'78a5636f'::bigint, x'84c87814'::bigint, x'8cc70208'::bigint,
        x'90befffa'::bigint, x'a4506ceb'::bigint, x'bef9a3f7'::bigint, x'c67178f2'::bigint
    ];
    h bigint[] := ARRAY[
        x'6a09e667'::bigint, x'bb67ae85'::bigint, x'3c6ef372'::bigint, x'a54ff53a'::bigint,
        x'510e527f'::bigint, x'9b05688c'::bigint, x'1f83d9ab'::bigint, x'5be0cd19'::bigint
    ];
    payload bytea;
    padded bytea;
    zeros integer;
    bit_len bigint;
    blocks integer;
    block integer;
    chunk bytea;
    w bigint[];
    j integer;
    v15 bigint;
    v2 bigint;
    s0 bigint;
    s1 bigint;
    a bigint;
    b bigint;
    c bigint;
    d bigint;
    e bigint;
    f bigint;
    g bigint;
    hh bigint;
    ch bigint;
    maj bigint;
    temp1 bigint;
    temp2 bigint;
    i integer;
    digest text := '';
BEGIN
    -- SHA-256 (FIPS 180-4) of the label, a NUL, and the stored output text.
    payload := convert_to('PRAETORE_EXECUTION_OUTPUT_V1', 'UTF8')
        || decode('00', 'hex')
        || convert_to(output_json, 'UTF8');
    bit_len := octet_length(payload) * 8;
    zeros := (56 - ((octet_length(payload) + 1) % 64) + 64) % 64;
    padded := payload
        || decode('80', 'hex')
        || decode(repeat('00', zeros), 'hex')
        || decode(lpad(to_hex(bit_len), 16, '0'), 'hex');
    blocks := octet_length(padded) / 64;
    FOR block IN 0 .. blocks - 1 LOOP
        chunk := substr(padded, block * 64 + 1, 64);
        w := array_fill(0::bigint, ARRAY[64]);
        FOR j IN 0 .. 15 LOOP
            w[j + 1] := ((get_byte(chunk, j * 4)::bigint) << 24)
                | ((get_byte(chunk, j * 4 + 1)::bigint) << 16)
                | ((get_byte(chunk, j * 4 + 2)::bigint) << 8)
                | (get_byte(chunk, j * 4 + 3)::bigint);
        END LOOP;
        FOR j IN 16 .. 63 LOOP
            v15 := w[j - 14];
            v2 := w[j - 1];
            s0 := ((v15 >> 7) | ((v15 << 25) & mask))
                # ((v15 >> 18) | ((v15 << 14) & mask))
                # (v15 >> 3);
            s1 := ((v2 >> 17) | ((v2 << 15) & mask))
                # ((v2 >> 19) | ((v2 << 13) & mask))
                # (v2 >> 10);
            w[j + 1] := (w[j - 15] + (s0 & mask) + w[j - 6] + (s1 & mask)) & mask;
        END LOOP;
        a := h[1];
        b := h[2];
        c := h[3];
        d := h[4];
        e := h[5];
        f := h[6];
        g := h[7];
        hh := h[8];
        FOR i IN 1 .. 64 LOOP
            s1 := ((e >> 6) | ((e << 26) & mask))
                # ((e >> 11) | ((e << 21) & mask))
                # ((e >> 25) | ((e << 7) & mask));
            ch := ((e & f) # ((~ e) & g)) & mask;
            temp1 := (hh + (s1 & mask) + ch + k[i] + w[i]) & mask;
            s0 := ((a >> 2) | ((a << 30) & mask))
                # ((a >> 13) | ((a << 19) & mask))
                # ((a >> 22) | ((a << 10) & mask));
            maj := ((a & b) # (a & c) # (b & c)) & mask;
            temp2 := ((s0 & mask) + maj) & mask;
            hh := g;
            g := f;
            f := e;
            e := (d + temp1) & mask;
            d := c;
            c := b;
            b := a;
            a := (temp1 + temp2) & mask;
        END LOOP;
        h[1] := (h[1] + a) & mask;
        h[2] := (h[2] + b) & mask;
        h[3] := (h[3] + c) & mask;
        h[4] := (h[4] + d) & mask;
        h[5] := (h[5] + e) & mask;
        h[6] := (h[6] + f) & mask;
        h[7] := (h[7] + g) & mask;
        h[8] := (h[8] + hh) & mask;
    END LOOP;
    FOR i IN 1 .. 8 LOOP
        digest := digest || lpad(to_hex(h[i]), 8, '0');
    END LOOP;
    RETURN digest;
END;
$output_digest$;

-- The insert trigger runs as the inserting role and calls this function, so
-- that role needs EXECUTE. PUBLIC EXECUTE is the grant allowed on a
-- function that is not SECURITY DEFINER; the function only hashes its
-- argument. REVOKE then GRANT fixes the ACL when default privileges have
-- removed the PUBLIC grant.
REVOKE ALL ON FUNCTION praetore.execution_output_digest_v1(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION praetore.execution_output_digest_v1(text) TO PUBLIC;

-- 0022's attestation INSERT rules, plus output_digest against output_json.
CREATE FUNCTION praetore.validate_execution_attestation_insert_v3()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, praetore, pg_temp
AS $$
DECLARE
    journal RECORD;
    state_matches BOOLEAN;
BEGIN
    -- Invoker rights: the row must be visible to the inserting role under
    -- row level security, so an attestation for another tenant's row is
    -- refused like a missing one. FOR SHARE keeps the row's state fixed
    -- until this transaction ends.
    SELECT current_row.authorization_status, current_row.execution_status,
           current_row.not_dispatched_reason, current_row.failure_class,
           current_row.failure_reason, current_row.action_digest,
           current_row.output_json
      INTO journal
      FROM praetore.execution_journal current_row
     WHERE current_row.tenant_id = NEW.tenant_id
       AND current_row.agent_id = NEW.agent_id
       AND current_row.request_id = NEW.request_id
       FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'execution attestation has no visible journal row';
    END IF;

    IF NEW.execution_status = 'awaiting_approval' THEN
        state_matches := journal.authorization_status = 'requires_approval'
            AND journal.execution_status = 'not_dispatched'
            AND journal.not_dispatched_reason IS NULL
            AND journal.failure_class IS NULL
            AND journal.failure_reason IS NULL
            AND NEW.not_dispatched_reason IS NULL
            AND NEW.failure_class IS NULL
            AND NEW.failure_reason IS NULL
            AND NEW.attestation_json -> 'schema_version' = '5'::jsonb
            AND NOT EXISTS (
                SELECT 1 FROM praetore.human_approvals approval
                WHERE approval.tenant_id = NEW.tenant_id
                  AND approval.agent_id = NEW.agent_id
                  AND approval.request_id = NEW.request_id
            )
            AND NOT EXISTS (
                SELECT 1 FROM praetore.human_approval_expirations expiration
                WHERE expiration.tenant_id = NEW.tenant_id
                  AND expiration.agent_id = NEW.agent_id
                  AND expiration.request_id = NEW.request_id
            );
    ELSE
        state_matches := NEW.execution_status = journal.execution_status
            AND NEW.not_dispatched_reason IS NOT DISTINCT FROM journal.not_dispatched_reason
            AND NEW.failure_class IS NOT DISTINCT FROM journal.failure_class
            AND NEW.failure_reason IS NOT DISTINCT FROM journal.failure_reason
            -- A held row is attested only as awaiting_approval, and schema
            -- version 5 is used only by awaiting_approval.
            AND NOT (journal.authorization_status = 'requires_approval'
                AND NEW.execution_status = 'not_dispatched'
                AND NEW.not_dispatched_reason IS NULL)
            AND NEW.attestation_json -> 'schema_version' IS DISTINCT FROM '5'::jsonb;
    END IF;

    IF NOT COALESCE(
        state_matches
        AND jsonb_typeof(NEW.attestation_json) = 'object'
        AND NEW.attestation_json ->> 'execution' = NEW.execution_status
        AND NEW.attestation_json ->> 'authorization' = journal.authorization_status
        AND NEW.attestation_json ->> 'tenant_id' = NEW.tenant_id::text
        AND NEW.attestation_json ->> 'agent_id' = NEW.agent_id::text
        AND NEW.attestation_json ->> 'request_id' = NEW.request_id::text
        AND NEW.attestation_json ->> 'action_digest' = journal.action_digest
        AND NEW.attestation_json ->> 'output_digest'
            IS NOT DISTINCT FROM praetore.execution_output_digest_v1(journal.output_json),
        false) THEN
        RAISE EXCEPTION 'execution attestation does not match the journal state: % (journal %)',
            NEW.execution_status, journal.execution_status;
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION praetore.validate_execution_attestation_insert_v3() FROM PUBLIC;

DROP TRIGGER execution_attestations_journal_state_v2 ON praetore.execution_attestations;
CREATE TRIGGER execution_attestations_journal_state_v3
BEFORE INSERT ON praetore.execution_attestations
FOR EACH ROW EXECUTE FUNCTION praetore.validate_execution_attestation_insert_v3();
