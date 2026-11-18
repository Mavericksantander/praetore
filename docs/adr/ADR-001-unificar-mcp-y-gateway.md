# ADR: Unificar praetore-mcp y praetore-gateway

## Estado

Propuesta. Nada de este documento está implementado ni decidido.

Base: `main` en `c6d9516`. Todas las rutas y líneas citadas son de ese commit.

Al subir este documento, `main` está en `0b01386`. Los símbolos citados
siguen ahí; en `crates/praetore-mcp/src/gate.rs` las líneas se movieron
(`Evaluator` está en la 156, `MemoryReplayGuard` en la 212, el motor se
construye en la 1048 y `impl Evaluator for Gate` está en la 1238). En
`crates/praetore-gateway/src/http_api.rs` y `lib.rs` los anclajes citados no
se movieron.

Nota de numeración: `docs/adr/` ya tiene los registros 001 a 006
(`docs/adr/README.md`). Este archivo lleva el nombre pedido; si se acepta,
el número libre siguiente es 007.

## Contexto

El repositorio tiene dos productos que solo comparten `praetore-core`.

**praetore-mcp** es un proxy stdio local.

- Lanza el servidor MCP como proceso hijo y relaya su stdio
  (`crates/praetore-mcp/src/relay.rs:459-466`).
- Evalúa cada `tools/call` con el motor HighAssurance de `praetore-core`,
  con un replay guard en memoria y una frescura local sin fuente de
  revocación (`crates/praetore-mcp/src/gate.rs:1031-1036`, `:207-227`,
  `:231-262`).
- Guarda en el home del usuario gobernado las cuatro claves (emisor, agente,
  atestador, aprobador), la política, el journal y las aprobaciones
  (`crates/praetore-mcp/src/store.rs:70-106`, `:147-211`;
  `crates/praetore-mcp/src/approvals.rs:1-12`).
- Su única dependencia del workspace es `praetore-core`
  (`crates/praetore-mcp/Cargo.toml:25`).

**praetore-gateway** es un servidor HTTP con Postgres.

- Rutas: `POST /v1/execute` y el flujo de aprobación con despacho único
  (`crates/praetore-gateway/src/http_api.rs:496-510`).
- Llamadores con token bearer atado a un tenant y dos roles, `Agent` y
  `Approver` (`http_api.rs:39-52`, `:84-95`, `:160-172`).
- Journal en Postgres con seguridad a nivel de fila por tenant
  (`crates/praetore-replay-postgres/migrations/0016_safety_records.sql:133-136`
  y las migraciones anteriores con la misma política `tenant_isolation`).
- Bandeja de aprobaciones y paquete de compliance en `praetore-console`
  (`crates/praetore-console/src/paquete.rs:1`).
- No habla MCP. Comando y resultado:
  `rg -c -i 'mcp' crates/praetore-gateway crates/praetore-gateway-service crates/praetore-console crates/praetore-observe crates/praetore-replay-postgres crates/praetore-receipt crates/praetore-sandbox-fs crates/praetore-safety-client crates/praetore-python packages deploy`
  no devuelve ninguna coincidencia (exit 1).

### Hechos del código que condicionan la decisión

**H1. La costura del lado MCP ya existe.** El proxy solo conoce el trait
`Evaluator`, con un método que devuelve un `Verdict`
(`crates/praetore-mcp/src/gate.rs:155-157`). `Gate` lo implementa
(`gate.rs:1224`) y `relay` lo carga en un solo punto (`relay.rs:420`).

**H2. Los dos productos ya usan el mismo tipo de petición.** `Gate` construye
un `AuthorizationRequest` y lo firma con la clave del agente como intención
v2 (`gate.rs:1158-1163`, `:1167-1196`). Ese mismo tipo es el cuerpo de
`POST /v1/execute`, que termina en `Gateway::execute`
(`crates/praetore-gateway/src/lib.rs:1478-1484`).

**H3. El gateway siempre ejecuta el efecto y rechaza la ejecución
cooperativa.** `Gateway` tiene un `ActionDispatcher` que realiza la acción
(`lib.rs:444-451`, `:673-679`). Fuera del modo de desarrollo, el API responde
409 a quien no declare que el efecto lo hace el gateway, y nunca le dice
`approved` a un agente que hace polling (`http_api.rs:219-241`;
`crates/praetore-gateway-service/src/exec_mode.rs:32-41`). Con un servidor
MCP stdio el efecto ocurre en el proceso hijo, en la máquina del usuario. Este
es el punto central de la decisión: ninguna de las dos opciones evita
resolverlo.

**H4. Un gateway tiene un motor y por tanto una política.** `Gateway`
contiene un solo `AuthorizationEngine` (`lib.rs:673-675`). En praetore-mcp la
política es por home.

**H5. Límites de tamaño distintos.** El gateway acepta cuerpos de hasta
64 KiB (`http_api.rs:25`, `:511`). El proxy acepta líneas de hasta 32 MiB
(`relay.rs:31`).

**H6. El transporte del gateway es HTTP/1 plano con JSON.** axum con
`http1`, `json` y `tokio`, sin streaming ni SSE
(`crates/praetore-gateway/Cargo.toml:13`), y sin TLS en el listener
(`crates/praetore-gateway-service/src/main.rs:714-728`).

**H7. Hay defensas que solo existen en el proxy.** La clasificación de líneas
ambiguas entre parsers (`crates/praetore-mcp/src/proxy.rs:35-52`) y la
resolución de rutas contra el sistema de archivos local
(`gate.rs:1123-1126`) viven en `praetore-mcp`, no en `praetore-core`.

**H8. No hay identidad federada.** `rg -n -i 'jsonwebtoken|\bjwt\b|\bjwks?\b|oidc|openid|saml|oauth|\bsso\b|scim|\bmfa\b|id[_-]token'`
sobre todo el árbol solo encuentra la firma de releases con la identidad OIDC
de GitHub Actions (`scripts/verify-release-signature.sh:4`, `:58`) y la frase
que declara la ausencia (`docs/tool-gateway-integration.md:634-636`).

## Opciones

### Opción A: praetore-mcp con un backend de gateway

El proxy local sigue siendo el punto de aplicación. El gateway pasa a decidir,
registrar y aprobar.

**Qué cambia y dónde**

| Archivo | Cambio |
|---|---|
| `crates/praetore-mcp/src/gate.rs:155-157` | Sin cambio en el trait. Una segunda implementación de `Evaluator` que envía el `AuthorizationRequest` firmado al gateway y traduce el recibo a `Verdict`. |
| `crates/praetore-mcp/src/gate.rs:1031-1036` | En modo gateway no se construye motor local: desaparecen de ese camino `MemoryReplayGuard` y `LocalFreshness`. El modo local los conserva. |
| `crates/praetore-mcp/src/relay.rs:420` | Elegir backend local o gateway según la configuración del home. |
| `crates/praetore-mcp/src/config.rs`, `store.rs:147-211` | URL del gateway y credencial. En modo gateway `init` crea solo la clave del agente; emisor, atestador y aprobador no se generan en el home. |
| `crates/praetore-mcp/Cargo.toml` | Un cliente HTTP con TLS. `praetore-cli` y `praetore-console` ya usan `reqwest` bloqueante con rustls. |
| `crates/praetore-mcp/src/approvals.rs` | No se usa en modo gateway. El mensaje de espera apunta a la bandeja del servidor. |
| `crates/praetore-gateway/src/http_api.rs:39-44`, `:219-241` | Un rol nuevo para el punto de aplicación delegado y un modo de ejecución sancionado en el que ese rol, y solo ese, reclama el despacho único y reporta el resultado. Hoy eso solo existe como modo de desarrollo sin garantías. |
| `crates/praetore-gateway/src/lib.rs:444-451`, `:1176`, `:1257` | Un `ActionDispatcher` que entrega la acción al punto de aplicación en vez de ejecutarla, apoyado en `claim_dispatch` y `dispatch`, que ya dan el reclamo único. |
| `crates/praetore-gateway/src/http_api.rs:25` | Decidir el límite de cuerpo frente a los 32 MiB del proxy (H5). `gate.rs:159-170` ya sustituye valores grandes por digests, así que la petición firmada es menor que la línea original. |

Existe un precedente del patrón de entrega con resultado diferido: el
supervisor de sandbox recibe la ejecución y el worker devuelve el resultado
por otra ruta
(`crates/praetore-gateway-service/src/sandbox_supervisor.rs:428-437`).

**Qué resuelve del delta de mercado**

| Brecha | Resultado |
|---|---|
| Claves fuera del gobernado | Sí para atestador, aprobador y emisor. La clave del agente sigue en el home (ver SAF-14). |
| Auditoría central | Sí. El journal queda en Postgres, por tenant, con el export encadenado existente. |
| Aprobación con cola | Sí, con la bandeja de `praetore-console`. Faltan notificaciones. |
| Identidad | Parcial. Hereda los tokens bearer por tenant. No trae OIDC. |

**Lo que no resuelve.** El usuario gobernado sigue controlando el punto de
aplicación: puede quitar el `wrap` de su configuración. Ya no puede fabricar
ni reescribir evidencia, pero una llamada que no pasa por el proxy no deja
recibo. Los hallazgos 6a a 6g de `install` siguen siendo necesarios.

**Riesgo técnico: medio.**

- Cada `tools/call` cuesta una ida y vuelta de red. En enforce, sin gateway
  no hay llamada (falla cerrado). Hay que definir qué hace observe sin red.
- El modo delegado toca H3, que es una garantía deliberada del gateway. El
  rol nuevo debe quedar separado de `Agent` por tipo, para que un agente no
  pueda reclamar su propio despacho.
- H4: hace falta decidir si la política es por tenant o por servidor MCP.

**Esfuerzo: medio.** Es una estimación, no una medición. Se apoya en que H1
y H2 ya existen: el cambio en `praetore-mcp` es una implementación nueva de
un trait de un método, y el trabajo mayor está en el modo delegado del
gateway y sus pruebas con Postgres.

### Opción B: el gateway habla MCP sobre HTTP

El cliente MCP se conecta al gateway. El gateway clasifica, decide y reenvía
al servidor MCP de destino. `praetore-mcp` queda como cliente ligero.

**Qué cambia y dónde**

| Archivo | Cambio |
|---|---|
| `crates/praetore-gateway/src/http_api.rs:496-510` | Una ruta MCP nueva en el router, con sesiones y respuestas en streaming. |
| `crates/praetore-gateway/Cargo.toml:13` | Transporte con streaming (H6) y TLS, o terminación TLS delante como requisito comprobado. |
| `crates/praetore-mcp/src/proxy.rs`, `json.rs` | Mover el clasificador y el parser estricto a un crate compartido. Hoy viven en `praetore-mcp` (`crates/praetore-mcp/src/lib.rs:16-18`) y el gateway no depende de él (H7). |
| `crates/praetore-gateway/src/lib.rs:444-451` | Un `ActionDispatcher` que sea cliente MCP del servidor de destino. |
| `crates/praetore-gateway-service/src/http_dispatcher.rs:31-39` | Las rutas estáticas por tenant y la inyección de credencial (`bearer_token_env`) se reutilizan para servidores MCP remotos. |
| `crates/praetore-core/src/authorization.rs`, `engine.rs` | Los clientes MCP no firman intenciones. O el gateway firma en nombre del llamador, con lo que la clave del agente pasa al servidor y la identidad es la del token, o se cambia el modelo de confianza del motor. Es un cambio de fondo, no de transporte. |
| `crates/praetore-mcp/src/gate.rs:1123-1126` | La comprobación de rutas contra el sistema de archivos local deja de tener sentido en el servidor. |

**Qué resuelve del delta de mercado**

| Brecha | Resultado |
|---|---|
| Claves fuera del gobernado | Sí, todas. |
| Auditoría central | Sí. |
| Aprobación con cola | Sí, igual que A. |
| Identidad | No por sí sola, pero la exige: un endpoint MCP remoto sin identidad federada no pasa una revisión de seguridad (inferencia de mercado, no evidencia del repo). |
| Punto de aplicación obligatorio | Sí para servidores MCP remotos, con la credencial retenida en el gateway. Es la única opción que lo da. |

**Lo que no resuelve.** Los servidores MCP stdio locales (sistema de
archivos, git, herramientas del equipo del desarrollador) no pueden
ejecutarse en el gateway. Para ellos el "cliente ligero" tendría que alojar
el proceso hijo y recibir órdenes del gateway, que es la opción A con otro
transporte y con el mismo H3.

**Riesgo técnico: alto.**

- Implementar el protocolo MCP del lado servidor y del lado cliente en un
  crate que hoy no tiene nada de MCP.
- El modelo de firma del agente (fila de `authorization.rs` arriba).
- La especificación MCP cambió de fondo en 2026 (inferencia de mercado; no
  la verifiqué contra la especificación oficial para este documento).

**Esfuerzo: alto.** Estimación. Incluye transporte, protocolo, extracción del
clasificador, identidad y la decisión sobre la firma del agente.

### Comparación

| Criterio | A | B |
|---|---|---|
| Servidores stdio locales | Sí | No sin reintroducir A |
| Servidores MCP remotos | No | Sí |
| Reutiliza código existente | `Evaluator`, `AuthorizationRequest`, `claim_dispatch`, bandeja | Router, rutas HTTP, credenciales |
| Conserva defensas del proxy (H7) | Sí | Hay que moverlas |
| Cambia el modelo de confianza del motor | No | Sí |
| Bypass por el usuario | Posible (quita el wrap) | No para servidores remotos |
| Necesita OIDC para ser vendible | Deseable | Imprescindible (inferencia) |
| Riesgo / esfuerzo | Medio / medio | Alto / alto |

## Decisión propuesta

Hacer A primero y dejar B como segundo frente, construido sobre las piezas de
servidor que A obliga a crear.

Razones:

1. A cubre los servidores que el producto ya gobierna hoy y que B no puede
   cubrir.
2. A se apoya en dos costuras que ya existen (H1, H2) y no cambia el modelo
   de confianza del motor.
3. El modo delegado, el rol nuevo y la identidad son prerrequisitos comunes.
   Hechos para A, B queda reducido a transporte, protocolo y la decisión
   sobre la firma del agente.
4. El modo local no se elimina. Sigue siendo el producto para una persona sin
   servidor y el modo sin red.

## Modelo de estados (modo gateway, opción A)

```
recibida --clasifica--> ambigua ---------------> rechazada (sin petición al gateway)
    │
    └-> firmada --POST /v1/execute--> sin respuesta --> rechazada (enforce)
                        │
                        ├- DENY -----------------------> rechazada
                        ├- ALLOW --reclamo único--> reenviada --resultado--> cerrada
                        └- REQUIRE_APPROVAL --> en espera
                                                   ├- rechazo / vencimiento --> cerrada sin efecto
                                                   └- aprobación --reclamo único--> reenviada --> cerrada
```

Invariantes que debe proteger la implementación:

- **I1.** El proxy no reenvía un `tools/call` al servidor MCP sin un recibo
  confirmado por el gateway para esa petición.
- **I2.** Una aprobación da como máximo un reclamo de despacho. Hoy lo
  garantiza `claim_dispatch` sobre el journal (`lib.rs:1169-1176`).
- **I3.** Un principal con rol `Agent` no puede reclamar un despacho ni
  decidir una aprobación.
- **I4.** Una línea que el clasificador marca como ambigua no genera petición
  al gateway en enforce.

## Pasos de migración

1. **Los cinco PR bloqueantes del modo local. Hecho.** #209 (B-NUM), #214
   (B-POISON), #215 (B-KEYS), #216 (B-PREFIX) y #217 (B-ANCHOR) están
   mergeados en `main` (`0b01386` los contiene). Iban antes porque el modo
   local permanece, porque #209 cambia qué número evalúa el gate en los dos
   modos, y porque #217 introduce el estado `UNANCHORED`
   (`crates/praetore-mcp/src/receipts.rs:193-199` en `0b01386`) que usa el
   paso 7.
2. **Elegir backend sin cambiar el comportamiento.** Configuración del home y
   selección en `relay.rs:420`, con el backend local como único disponible.
3. **Modo delegado en el gateway.** Rol nuevo, reclamo de despacho por el
   punto de aplicación y reporte de resultado, con pruebas en el job de
   Postgres. Requiere reemplazar o extender la decisión documentada en
   `ExecMode` (`http_api.rs:219-241`).
4. **Backend de gateway en praetore-mcp, solo enforce.** Segunda
   implementación de `Evaluator`. Observe en una entrega posterior.
5. **Aprobaciones en el servidor.** La espera apunta a la bandeja; el proxy
   consulta el estado y reclama el despacho.
6. **Claves e identidad del agente.** `init` en modo gateway crea solo la
   clave del agente y el servidor emite la autoridad. Es el alcance de
   `docs/proposals/SAF-14-identidad-por-agente.md`, que hoy es propuesta.
7. **Ancla externa (SAF-13).** `docs/proposals/SAF-13-anclaje-del-head-del-journal.md`
   es solo documento. Entra en dos sitios:
   - en el servidor, sobre el head del export por tenant
     (`crates/praetore-replay-postgres/src/journal_export.rs:46-52`), que es
     un único lugar para todos los proxies;
   - en el modo local, como la forma de pasar de `UNANCHORED` a anclado sin
     depender de que el usuario guarde el head a mano.
   Va después del paso 4 para anclar el journal que ya es central, pero no
   depende de B.
8. **Identidad federada** para los principales del API. Es común a A y B.
9. **Opción B** para servidores MCP remotos, con el clasificador extraído a
   un crate compartido.

## Consecuencias

- `praetore-mcp` gana una dependencia de red y un segundo modo. El modo local
  y sus garantías no cambian.
- El gateway deja de ser "siempre ejecuta el efecto" (H3). Es el cambio de
  más riesgo y necesita su propio registro de decisión.
- Aparece una pregunta de producto que el código no responde: política por
  tenant o por servidor MCP (H4).

## Verificación

Cada invariante debe cerrarse con un tipo o un test, y con una mutación que
lo rompa:

- I1: test de integración que corta la respuesta del gateway y comprueba que
  el servidor falso no registra la ejecución.
- I2: ya cubierto del lado del journal; añadir el caso de dos proxies que
  reclaman a la vez.
- I3: el rol del punto de aplicación como variante propia de `ApiRole`, con
  un test por ruta.
- I4: reutilizar los casos de `crates/praetore-mcp/src/proxy.rs` contra el
  backend de gateway.

## Sin verificar

- No se ejecutó ni compiló nada para este documento. Es lectura de código.
- Las líneas de las migraciones anteriores a 0016 y del supervisor de
  sandbox, salvo las rutas citadas, vienen de un sondeo de lectura y no las
  releí una por una.
- Los esfuerzos son estimaciones cualitativas.
- Las afirmaciones marcadas como inferencia de mercado no salen del repo.
