# ADOPT-01 · Adopción local: proxy MCP, instalación y consola (propuesta)

Estado: **propuesta.** Ninguna decisión está tomada; cada una espera la
aprobación del CTO. El paso 1 tiene una implementación de prueba en la rama
`feat/mcp-proxy` (PR en borrador) para poder evaluarlo antes de decidir.
Nombre: `ADOPT-NN` es provisional. Los `SAF-NN` cubren semántica de seguridad,
y esto es empaquetado y experiencia de desarrollador.
Base: `main` en `0595422`.

## 1. Problema

Hoy adoptar PRÆTORE requiere:
- integrar la librería en Rust, o usar `praetore-gateway-service` con
  PostgreSQL;
- generar y fijar llaves (issuer, agente, attester) a mano;
- que el agente construya y firme un `AuthorizationRequest` por sí mismo.

Un equipo que usa agentes de IA a través de clientes MCP (Claude Desktop,
Cursor, VS Code) no puede probarlo en minutos. La propuesta busca que pueda
hacerlo **sin perder** lo que distingue a PRÆTORE: decisiones deterministas
y recibos firmados que un tercero verifica sin confiar en nosotros.

## 2. Lo que ya existe (verificado)

| Pieza | Estado |
|---|---|
| Binario de servicio (`praetore-gateway-service`) con API HTTP | Existe. Rutas fijas; el agente envía un `AuthorizationRequest` firmado. No intercepta tráfico de terceros. |
| Verificación offline (`praetore-verify`, `verify.sh`, `demo/verify-receipt.sh`) | Existe. |
| Consola web local de solo lectura (`praetore-observe`) | Existe. Loopback, autenticada y respaldada por PostgreSQL. |
| Journal | Solo PostgreSQL. |
| Bindings de Python | Solo verificación. |

## 3. Decisiones propuestas

| # | Decisión | Estado |
|---|---|---|
| 1 | El primer punto de entrada es un **proxy MCP por stdio** (`praetore-mcp wrap -- <servidor>`) que evalúa cada `tools/call`. LangChain, LlamaIndex y HTTP/SSE vienen después. gRPC no está en el alcance. | PROPUESTA |
| 2 | **Modelo de confianza explícito:** el proxy firma con su propia identidad local. Sus recibos atestiguan "el proxy vio o autorizó esta llamada", no que el agente o el LLM la haya firmado. La documentación lo dice en la primera página. | PROPUESTA |
| 3 | **Modo observación** por defecto en la instalación local: siempre reenvía y solo registra. El modo queda **dentro de la evidencia firmada** (`context["praetore.mode"] = "observe"`), de modo que un recibo de observación nunca pueda presentarse como enforcement. `enforce` se activa explícitamente. | PROPUESTA |
| 4 | El modo local no usa PostgreSQL. Los recibos se guardan en un **journal append-only JSONL** que se verifica con las herramientas existentes. SQLite queda para cuando la consola necesite consultas. PostgreSQL sigue siendo el journal de producción. | PROPUESTA |
| 5 | La **instalación** modifica la configuración del cliente (`claude_desktop_config.json`, `~/.cursor/mcp.json`, la de VS Code) solo con confirmación o `--yes`, siempre con backup y `--dry-run`, y `uninstall` restaura exactamente lo original. | PROPUESTA |
| 6 | **Distribución con binarios firmados** y checksums (el CI ya publica checksums de release), más Homebrew. No se promociona `curl \| bash`. Si existe un script, solo descarga, verifica la firma y no ejecuta nada más. | PROPUESTA |
| 7 | **Consola:** se amplía `praetore-observe` (gráficos de decisiones en el tiempo, filtros por servidor y herramienta, detalle de recibo con su verificación). Editar reglas desde la UI crea **una nueva versión de la política** con su digest y un registro de auditoría. Nunca se edita "en caliente" una política fijada. | PROPUESTA |
| 8 | **Sin puntajes de riesgo que influyan en decisiones.** El motor sigue siendo determinista, como cuando se excluyó la reputación al portar Canopy. Si se muestra un indicador, es informativo y no entra en la política. | PROPUESTA |
| 9 | En `praetore-mcp`, RequireApproval se trata como Deny hasta integrar el flujo de aprobación firmado del gateway. | PROPUESTA |

## 4. Fuera de alcance

- Interceptar tráfico del LLM ("flujos de tokens"): PRÆTORE autoriza acciones,
  no conversaciones.
- Interceptar procesos que no pasan por el proxy. El enforcement sigue siendo
  cooperativo (ver Limitaciones en el README): un usuario puede deshacer la
  configuración.

## 5. Pasos

1. **`praetore-mcp`** (rama `feat/mcp-proxy`):
   - `init`: llaves locales, autoridad y política por defecto.
   - `wrap`: el proxy, en modos observe y enforce.
   - `install` / `uninstall` para Claude Desktop, Cursor y VS Code.
   - `receipts` y `verify`.
2. **Distribución:** releases firmados (macOS, Linux, Windows), fórmula de
   Homebrew, y verificación de firma documentada.
3. **Consola local:** `praetore-observe` lee el journal local (SQLite o
   JSONL) además de PostgreSQL, y agrega las vistas y la edición versionada
   de políticas de la decisión 7.
4. **Wrappers de frameworks:** cliente de Python que habla con el gateway
   (LangChain/LlamaIndex como callbacks de herramientas) y transporte
   HTTP/SSE para MCP.

## 6. Riesgos

- **Competir en el terreno de otros:** si se copia una herramienta de
  observabilidad de agentes punto por punto, se pierde la diferencia. El
  mensaje de producto debe empezar por los recibos verificables por terceros.
- **El modo observación crea una falsa sensación de control:** por eso el
  modo va dentro de la evidencia firmada y la consola lo muestra en cada fila.
- **Llaves locales:** son de desarrollo. Pasar a producción exige las llaves,
  pines y frescura del gateway (ver `docs/operations.md`).

## 7. Pendientes para el CTO

- Aprobar o ajustar las decisiones 1–9.
- Confirmar el nombre `ADOPT-NN`.
- Decidir si `praetore-mcp` vive en este repo (open core) o en uno separado.
- La licencia actual es no comercial: definir qué licencia aplica a la
  distribución binaria pensada para adopción masiva.
