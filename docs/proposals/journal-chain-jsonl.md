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

El link es un SHA-256 **sin clave** y nadie firma ni publica el `head`. Por
eso el formato, tal como está, **no** prueba que no se borró un recibo:

- **Borrado en el medio, reordenamiento, inserción de recibos firmados
  válidos:** no se detectan. Quien tenga el archivo puede quitar o mover
  líneas y recalcular `seq` y `prev` de las siguientes; el verificador
  acepta el resultado. Solo detecta ediciones de alguien que no recalcula
  la cadena (errores accidentales, no un adversario).
- **Truncado del final:** no se detecta. Un prefijo de una cadena válida es
  una cadena válida, y no hay `head` esperado contra el cual comparar.
- **Fork / equivocación:** no se detecta. El productor puede entregar
  cadenas distintas a distintos auditores; cada una verifica.
- **Reemplazo completo por una cadena recalculada:** no se detecta mientras
  use recibos firmados por el atestador (cualquier subconjunto, en cualquier
  orden). Lo único que no se puede es fabricar recibos: eso ya lo impide la
  firma de cada recibo, no la cadena.
- Tampoco prueba que el export esté completo respecto del journal, ni que el
  orden registrado sea el orden real de las decisiones, ni nada sobre la
  autorización vigente, la frescura o el estado de replay.

## Qué falta para que un tercero pruebe que no se borró nada

1. **Cadena calculada al escribir, no al exportar.** El link (o una hoja de
   un árbol de Merkle) se calcula en la misma transacción que inserta el
   recibo en el journal, con `seq` asignado por la base sin huecos.
2. **Head firmado.** El atestador (o la clave del gateway) firma
   periódicamente `(seq, head, timestamp)` con un dominio propio, y el
   verificador exige `--expected-head` o un head firmado contra la clave
   fijada. Sin esto el truncado y el recálculo pasan.
3. **Mejor aún, ligar el `prev` dentro del recibo firmado**, para que la
   firma de cada recibo cubra su posición y no se pueda reencadenar sin la
   clave del atestador.
4. **Consistencia append-only entre heads** (árbol de Merkle estilo
   RFC 6962/9162, pruebas de consistencia e inclusión), para que un auditor
   con un head antiguo verifique que el nuevo lo extiende.
5. **Anclaje externo contra fork:** publicar los heads firmados fuera del
   control del operador (testigos que cofirman, un log de transparencia o un
   canal público) y que los auditores comparen heads entre sí.
6. **Liveness:** que la ausencia de un head nuevo dentro de un plazo sea en sí
   una falla visible; si no, el operador puede dejar de publicar.

Incluso con todo esto, la cadena solo cubre lo que entra al journal: no
prueba que una decisión tomada fuera del gateway quede registrada.
