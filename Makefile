# Walkthrough demo of the kernel. See docs/DEMO.md.
# Both targets only call commands that already exist in the repository.

DEMO_DIR ?= target/praetore-demo
VERIFY = cargo run --locked -q -p praetore-verify -- journal \
	--attester-pin $(DEMO_DIR)/attester-public-key.hex \
	--policy $(DEMO_DIR)/policy.json \
	--expected-head "$$(cat $(DEMO_DIR)/expected-head.txt)"

.PHONY: demo demo-verify

demo:
	cargo run --locked -q -p praetore-core --example demo -- $(DEMO_DIR)

# Re-checks the chain written by `make demo` with the separate praetore-verify
# binary: the original must verify and the altered copy must be rejected.
demo-verify:
	@echo "== praetore-verify: cadena original (debe verificar)"
	@$(VERIFY) --journal $(DEMO_DIR)/journal.jsonl
	@echo "== praetore-verify: copia alterada (debe ser rechazada)"
	@if $(VERIFY) --journal $(DEMO_DIR)/journal-tampered.jsonl; then \
		echo "FALLO: la copia alterada fue aceptada"; exit 1; \
	else \
		echo "OK: la copia alterada fue rechazada"; \
	fi
