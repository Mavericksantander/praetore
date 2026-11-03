# Walkthrough demo of the kernel. See docs/DEMO.md.
# Both targets only call commands that already exist in the repository.

DEMO_DIR ?= target/praetore-demo
VERIFY = cargo run --locked -q -p praetore-verify -- journal \
	--attester-pin "$(DEMO_DIR)/attester-public-key.hex" \
	--policy "$(DEMO_DIR)/policy.json" \
	--expected-head "$$(cat "$(DEMO_DIR)/expected-head.txt")"

.PHONY: demo demo-verify

demo:
	@echo "Compilando y ejecutando la demo (la primera vez tarda entre 20 s y unos minutos)..."
	@cargo run --locked -q -p praetore-core --example demo -- "$(DEMO_DIR)"

# Re-checks the files written by `make demo` with the separate praetore-verify
# binary. The original must verify; each altered copy must fail with its
# specific code (any other failure, such as a missing file, is an error).
demo-verify: demo
	@echo
	@echo "== praetore-verify: cadena original (debe verificar)"
	@$(VERIFY) --journal "$(DEMO_DIR)/journal.jsonl"
	@echo "== praetore-verify: recibo alterado (debe fallar con EVIDENCE_FAIL)"
	@out="$$($(VERIFY) --journal "$(DEMO_DIR)/journal-tampered.jsonl" 2>&1)"; status=$$?; \
	echo "$$out"; \
	if [ $$status -eq 0 ] || ! echo "$$out" | grep -q 'EVIDENCE_FAIL'; then \
		echo "FALLO: se esperaba EVIDENCE_FAIL"; exit 1; fi; \
	echo "OK: rechazada"
	@echo "== praetore-verify: recibo borrado y enlaces recalculados (debe fallar con JOURNAL_HEAD_MISMATCH)"
	@out="$$($(VERIFY) --journal "$(DEMO_DIR)/journal-relinked.jsonl" 2>&1)"; status=$$?; \
	echo "$$out"; \
	if [ $$status -eq 0 ] || ! echo "$$out" | grep -q 'JOURNAL_HEAD_MISMATCH'; then \
		echo "FALLO: se esperaba JOURNAL_HEAD_MISMATCH"; exit 1; fi; \
	echo "OK: rechazada (solo porque se compara contra el head esperado)"
