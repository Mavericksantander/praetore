# Demo: verificación por terceros con `praetore-verify`

Este directorio permite que alguien externo a PRÆTOR verifique un recibo de
evidencia (`evidence.json`) por su cuenta, desde un clon limpio y con
herramientas gratuitas.

> **Claves DEMO.** Todo lo que hay en `bundle/` se generó con claves de demo
> fijas y públicas (bytes secretos `[0xd1; 32]` agente, `[0xd2; 32]` emisor,
> `[0xd3; 32]` atestador). No autorizan nada y no se deben usar fuera de este
> demo. Los identificadores y nombres llevan el prefijo `DEMO`.

## Requisitos

- `git`
- `cargo` (Rust stable; el repo fija la versión mínima en `Cargo.toml`)
- `python3` con `venv` y `pip`. El paso Python instala el paquete local
  `packages/praetore-python` en un entorno virtual temporal. Para eso `pip`
  descarga `maturin` desde PyPI y compila la extensión con Rust. Se puede
  omitir con `PRAETORE_SKIP_PYTHON=1`.

## Pasos

```sh
git clone https://github.com/Mavericksantander/praetore.git
cd praetore
./examples/third-party-verification/verify.sh
```

El script sale con código 0 solo si todas las verificaciones dan lo
esperado. Hace lo siguiente:

1. Compila `praetore-verify` con `cargo build --release --locked`.
2. Verifica `bundle/evidence.json` con
   `praetore-verify evidence --attester-pin ... --issuer-pins ... --require-intent`.
3. Calcula el digest de `bundle/policy.json` con `praetore-verify policy-digest`
   y comprueba que es igual al `policy_digest` ligado en la evidencia; luego
   repite la comprobación con `praetore-verify evidence --policy bundle/policy.json`.
4. Verifica `bundle/authority.json` con `praetore-verify authority --agent ...`
   en una fecha fija (`2026-10-24T00:00:00Z`).
5. Copia la evidencia, cambia **un byte** (una letra de `decision.reason`) y
   comprueba que la verificación falla (`EVIDENCE_FAIL`, exit 1).
6. Repite la verificación de la evidencia válida y de la alterada con el
   verificador Python (`praetore.verify_evidence_integrity` y
   `praetore.verify_evidence_attester_signature`).

## Qué se verifica

| Comprobación | Herramienta | Qué significa |
|---|---|---|
| Integridad del documento | `praetore-verify evidence`, Python | El `context_hash` (SHA-256 del JSON canónico) coincide con el contenido, el formato corresponde a la versión declarada y no hay claves JSON duplicadas. Cualquier cambio de contenido lo rompe. |
| Firma del atestador | `praetore-verify evidence`, Python | Firma Ed25519 sobre el recibo, con la clave pineada en `attester-public-key.hex`; el `attester_key_id` debe corresponder a esa clave. |
| Autoridad del agente | `praetore-verify evidence --issuer-pins` | La autoridad embebida está firmada por el emisor pineado en `issuer-pins.jsonl` (mismo `issuer` y `issuer_key_id`), está dentro de su ventana de validez **a la hora actual**, y su sujeto corresponde a la clave del agente embebido. |
| Intención del agente | `praetore-verify evidence --require-intent` | La solicitud está firmada por la clave del agente. |
| Digest de la política | `praetore-verify evidence --policy`; también `policy-digest` más comparación en `verify.sh` | La política publicada en `policy.json` es la misma cuyo digest quedó ligado en la evidencia, y la firma del atestador cubre ese digest. Un recibo sin `policy_digest` falla con `POLICY_MISMATCH`. |
| Autoridad sola | `praetore-verify authority --agent` | Firma del emisor, ventana de validez en la fecha `--now` y ligadura con la identidad del agente. |

El verificador Python solo cubre integridad y firma del atestador. No
verifica autoridad, intención ni política.

### Versiones de evidencia

`praetore-verify` lee las tres versiones de `evidence_schema_version`:

- **v1:** recibo base (modo desarrollo). Firma con dominio `PRAETORE_EVIDENCE_V1`.
- **v2:** recibo HighAssurance, con `decided_at`, `freshness_valid_until`,
  `authority_digest`, `semantics_version` y firma de atestador obligatoria.
  Usa el dominio de firma `PRAETORE_EVIDENCE_V2`.
- **v3:** recibo que lleva una obligación de recuperación (`decision.recovery`,
  SAF-10).

El bundle de este demo es **v1**. Este demo no ejercita v2 ni v3.

## Qué NO garantiza

- **No es autorización vigente.** El propio comando lo reporta:
  `"current_authorization": false` y
  `"verification_scope": "historical_receipt_integrity_and_attestation"`.
  Un recibo válido no da permiso para ejecutar nada ahora.
- No comprueba frescura, replay ni revocación de claves o autoridades.
- No vuelve a evaluar la política: no prueba que la decisión registrada sea
  la que la política habría producido. Solo prueba que el recibo no cambió y
  quién lo firmó.
- No prueba que la acción se haya ejecutado, ni su resultado.
- No hay cadena de hash entre recibos: cada recibo se verifica por separado,
  así que el demo no detecta recibos faltantes, reordenados o duplicados en
  un registro.
- La confianza depende de los pines (`attester-public-key.hex`,
  `issuer-pins.jsonl`). Si un tercero los toma del mismo lugar que la
  evidencia, solo verifica consistencia interna. En un uso real los pines
  deben llegar por un canal independiente.
- La ventana de la autoridad DEMO vence el `2036-01-01T00:00:00Z`. Desde
  entonces el paso 2 falla y hay que regenerar el bundle.

## Regenerar el bundle

```sh
./examples/third-party-verification/regenerate.sh
```

El script usa `crates/praetore-core/examples/third_party_bundle.rs`. Las
claves, los identificadores y las fechas son fijos y las firmas Ed25519 son
deterministas, así que la salida es idéntica byte a byte en cada corrida
(`git diff` queda vacío).

## Test

`crates/praetore-verify/tests/third_party_bundle.rs` corre el binario sobre el
bundle versionado, comprueba que una alteración de un byte da `EVIDENCE_FAIL`
y que el digest de la política coincide. Lo ejecuta `cargo test --workspace`.
