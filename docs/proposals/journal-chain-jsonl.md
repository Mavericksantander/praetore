# Propuesta: export encadenado del journal (JSONL)

**Estado: propuesta.** No implementado en `main`. Ningún componente produce
este formato. Un verificador de referencia quedó en la rama
`feat/journal-chain-verifier` (commit `bfeade5`, subcomando
`praetore-verify journal`), fuera de cualquier PR.

El productor (exportador desde el journal Postgres) y el verificador irán
juntos en un único PR futuro. Así no se publica un verificador para un
formato que nadie genera.

## Formato

- Archivo UTF-8, una entrada por línea (`\n`), sin líneas vacías. Un archivo
  vacío es inválido.
- Cada línea es un objeto JSON con exactamente estos campos (cualquier otro
  campo se rechaza):
  - `seq`: entero sin signo. Es 0 en la primera línea y aumenta de 1 en 1.
  - `prev`: 64 caracteres hex en minúsculas. En la primera línea son 64
    ceros. En las siguientes es el `link` de la entrada anterior.
  - `evidence`: un recibo `Evidence` completo, tal como lo emite
    `Evidence::to_json`. Se valida con `Evidence::from_json`, que rechaza
    claves duplicadas y campos desconocidos.
- Cada `evidence_id` aparece una sola vez en el archivo.

## Link

```
link = lowercase_hex( SHA-256(
    b"PRAETORE_JOURNAL_LINK_V1\0"     // 25 bytes, incluye el NUL final
 || u64_big_endian(seq)               // 8 bytes
 || ascii(prev)                       // 64 bytes: hex en minúsculas, no decodificado
 || ascii(evidence.context_hash)      // 64 bytes: hex tal como está en el recibo
 || ascii(evidence.attester_signature)// 128 bytes: hex tal como está en el recibo
))
```

Los campos se concatenan sin separadores. Un recibo sin `attester_signature`
hace fallar la cadena. El `link` de la última entrada es el `head` del
export.

## Verificación

Para cada línea, en orden:

1. La línea parsea según el formato.
2. `seq` es el esperado y `prev` coincide con el link anterior.
3. La firma Ed25519 del recibo es válida contra la clave de attester fijada.
4. El `evidence_id` no se repite.
5. Si se pasa `--policy`, el recibo registra ese digest de política
   (`Evidence::verify_policy`).

Cualquier fallo termina con exit distinto de 0. El comportamiento es
fail-closed.

## Límites

- 8 MiB por archivo.
- 4096 entradas.
- 64 KiB por recibo, que es el límite existente de `Evidence::from_json`.

## Qué NO prueba

- Solo prueba la integridad del export: que nadie reordenó, quitó, insertó,
  duplicó ni alteró recibos después de generarlo.
- No prueba que el orden registrado sea el orden real original en que se
  tomaron las decisiones. Ese orden lo fija el productor.
- No prueba que el export esté completo respecto del journal.
- No dice nada sobre la autorización vigente, la frescura ni el estado de
  replay.
