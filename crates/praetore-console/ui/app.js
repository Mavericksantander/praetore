// The console page. Every text is set with textContent; the server sends
// codes and instants, and this page words them with the catalog of the
// chosen language (ui/i18n/*.json). The language is presentation only: no
// request carries it, and nothing the console signs, records or exports
// depends on it.
import { IDIOMAS, LLAVE_IDIOMA, crearTraductor, elegirIdioma } from "./i18n.js";
import { formatearInstante, tiempoRestante } from "./hora.js";

// Session: the token is minted by the console and handed out once through the
// opening link's URL fragment (`#abrir=`), which the browser never sends to
// the server. It is kept in sessionStorage, scoped to the opening tab's
// origin, and sent as `Authorization: Bearer` on every request. No cookie
// carries the session.
const LLAVE_SESION = "praetore_sesion";

function tokenSesion() {
  return sessionStorage.getItem(LLAVE_SESION);
}

function cabeceras(extra) {
  const base = { "x-praetore-consola": "1" };
  const token = tokenSesion();
  if (token) base["Authorization"] = "Bearer " + token;
  return extra ? Object.assign(base, extra) : base;
}

function olvidarSiCaduco(response) {
  if (response.status === 401) sessionStorage.removeItem(LLAVE_SESION);
}

function codigoDelHash() {
  const marca = "#abrir=";
  const hash = window.location.hash || "";
  return hash.startsWith(marca) ? hash.slice(marca.length) : null;
}

async function abrirSesion(codigo) {
  try {
    const response = await fetch("/api/sesion", {
      method: "POST",
      headers: { "x-praetore-consola": "1", "content-type": "application/json" },
      body: JSON.stringify({ codigo }),
    });
    olvidarSiCaduco(response);
    if (!response.ok) return false;
    const data = await response.json();
    if (data && typeof data.token === "string") {
      sessionStorage.setItem(LLAVE_SESION, data.token);
      return true;
    }
  } catch (_error) {
    return false;
  }
  return false;
}

// Language. The choice is kept in localStorage under LLAVE_IDIOMA (never the
// session); the server is never told.
let idioma = "es";
let t = crearTraductor({}, idioma);
const zona = Intl.DateTimeFormat().resolvedOptions().timeZone;

function idiomaGuardado() {
  try {
    return localStorage.getItem(LLAVE_IDIOMA);
  } catch (_error) {
    return null;
  }
}

function guardarIdioma(valor) {
  try {
    localStorage.setItem(LLAVE_IDIOMA, valor);
  } catch (_error) {
    // Not kept: the page still works in the chosen language.
  }
}

async function leerCatalogo(valor) {
  try {
    const response = await fetch("/i18n/" + valor + ".json");
    if (!response.ok) return null;
    const catalogo = await response.json();
    return catalogo && typeof catalogo === "object" ? catalogo : null;
  } catch (_error) {
    return null;
  }
}

// Each request for a language gets a number; only the latest one is used,
// so two quick changes cannot leave the page in one language and the
// selector in another.
let ultimoPedidoDeIdioma = 0;

// Without a catalog the Spanish already in the page stays.
async function usarIdioma(valor) {
  const turno = ++ultimoPedidoDeIdioma;
  const catalogo = await leerCatalogo(valor);
  if (!catalogo || turno !== ultimoPedidoDeIdioma) return false;
  idioma = valor;
  t = crearTraductor(catalogo, valor);
  document.documentElement.setAttribute("lang", valor === "pt" ? "pt-BR" : valor);
  for (const nodo of document.querySelectorAll("[data-i18n]")) {
    nodo.textContent = t(nodo.getAttribute("data-i18n"));
  }
  const selector = document.getElementById("idioma");
  if (selector) selector.value = valor;
  return true;
}

// Texts that depend on the language are kept as functions, so a change of
// language words them again.
const textos = new Map();

function decir(nodo, texto) {
  textos.set(nodo, texto);
  nodo.textContent = texto();
}

function hora(iso, segundos) {
  return formatearInstante(iso, idioma, zona, { segundos });
}

// Agent text (already quoted or made inert by the console), or the code of
// what is shown in its place.
function mostrado(valor) {
  if (valor && typeof valor.texto === "string") return valor.texto;
  if (valor && typeof valor.codigo === "string") return t("value." + valor.codigo);
  return t("value.not_shown");
}

function etiquetaAgente(agente) {
  if (agente && typeof agente.nombre === "string") return agente.nombre;
  if (agente && Number.isInteger(agente.numero)) return t("agent.numbered", { numero: agente.numero });
  return t("agent.unknown");
}

function mensaje(valor, respaldo) {
  if (valor && typeof valor.codigo === "string") return t("message." + valor.codigo, valor);
  return t(respaldo);
}

const estado = document.getElementById("estado");
const aviso = document.getElementById("aviso");
const lista = document.getElementById("lista");
const detalle = document.getElementById("detalle");
const paginaTexto = document.getElementById("pagina");
let pagina = 1;
let paginas = 1;
let ultimaLista = null;
let ultimoDetalle = null;

function consulta() {
  const datos = new FormData(document.getElementById("filtros"));
  const parametros = new URLSearchParams();
  for (const [clave, valor] of datos.entries()) {
    const texto = String(valor).trim();
    if (texto !== "") parametros.set(clave, texto);
  }
  return parametros;
}

function campo(etiqueta, valor) {
  const bloque = document.createElement("div");
  bloque.className = "detail-field";
  const titulo = document.createElement("span");
  titulo.textContent = etiqueta;
  const contenido = document.createElement("strong");
  contenido.textContent = valor;
  bloque.append(titulo, contenido);
  return bloque;
}

function pintarLista(data) {
  lista.replaceChildren();
  decir(paginaTexto, () => t("history.page", { pagina: data.pagina }));
  document.getElementById("anterior").disabled = data.pagina <= 1;
  document.getElementById("siguiente").disabled = data.pagina >= data.paginas;
  decir(aviso, () => t("notice." + data.aviso));
  decir(estado, () => t("history.count", { n: data.total }));
  if (!data.recibos.length) {
    const vacio = document.createElement("li");
    vacio.className = "vacio";
    vacio.textContent = t("history.empty");
    lista.append(vacio);
    return;
  }
  for (const recibo of data.recibos) {
    const item = document.createElement("li");
    const boton = document.createElement("button");
    boton.type = "button";
    boton.className = "recibo";
    const situacion = document.createElement("strong");
    situacion.textContent = t("situation." + recibo.situacion);
    const cuando = document.createElement("span");
    cuando.textContent = hora(recibo.cuando_utc, false);
    const agente = document.createElement("span");
    agente.textContent = etiquetaAgente(recibo.agente);
    const queria = document.createElement("span");
    queria.textContent = t("field.wanted") + ": " + mostrado(recibo.queria);
    const sobre = document.createElement("span");
    sobre.textContent = t("field.on") + ": " + mostrado(recibo.sobre);
    boton.append(situacion, cuando, agente, queria, sobre);
    boton.addEventListener("click", () => abrir(recibo.abrir));
    item.append(boton);
    lista.append(item);
  }
}

async function cargar() {
  decir(estado, () => t("history.loading"));
  detalle.classList.add("hidden");
  ultimoDetalle = null;
  const parametros = consulta();
  parametros.set("pagina", String(pagina));
  let response;
  try {
    response = await fetch("/api/historial?" + parametros.toString(), { headers: cabeceras() });
  } catch (_error) {
    decir(estado, () => t("history.read_failed"));
    return;
  }
  olvidarSiCaduco(response);
  if (response.status === 401) {
    decir(estado, () => t("session.open_link"));
    return;
  }
  if (!response.ok) {
    decir(estado, () => t("history.read_failed"));
    return;
  }
  const data = await response.json();
  paginas = data.paginas || 1;
  ultimaLista = data;
  pintarLista(data);
}

function pintarDetalle(data) {
  detalle.classList.remove("hidden");
  detalle.replaceChildren();
  const titulo = document.createElement("h2");
  titulo.textContent = t("situation." + data.situacion);
  const grilla = document.createElement("div");
  grilla.className = "detail-grid";
  grilla.append(
    campo(t("field.when"), hora(data.cuando_utc, false)),
    campo(t("field.updated"), hora(data.actualizado_utc, false)),
    campo(t("field.agent"), etiquetaAgente(data.agente)),
    campo(t("field.wanted"), mostrado(data.queria)),
    campo(t("field.on"), mostrado(data.sobre)),
  );
  const relato = document.createElement("p");
  relato.textContent = t("story." + data.relato);
  const nota = document.createElement("p");
  nota.className = "aviso";
  nota.textContent = t("notice." + data.aviso);
  detalle.append(titulo, grilla, relato, nota);
}

async function abrir(numero) {
  const parametros = consulta();
  let response;
  try {
    response = await fetch("/api/historial/" + numero + "?" + parametros.toString(), {
      headers: cabeceras(),
    });
  } catch (_error) {
    decir(estado, () => t("history.open_failed"));
    return;
  }
  olvidarSiCaduco(response);
  if (!response.ok) {
    decir(estado, () => t("history.open_failed"));
    return;
  }
  const data = await response.json();
  ultimoDetalle = data;
  pintarDetalle(data);
  detalle.scrollIntoView({ block: "nearest" });
}

const bandejaEstado = document.getElementById("bandeja-estado");
const bandejaAviso = document.getElementById("bandeja-aviso");
const solicitudes = document.getElementById("solicitudes");
// Cards on screen; each words itself again when the language changes.
let tarjetas = [];

function linea(texto) {
  const span = document.createElement("span");
  span.textContent = texto;
  return span;
}

// The route of each action, chosen by its code. No route depends on the
// text of a button.
const RUTAS = Object.freeze({ approve: "aprobar", reject: "rechazar", execute: "ejecutar" });

function sinCambios(puedeEjecutar) {
  return {
    situacion: "unchanged",
    mensaje: { codigo: "outcome_unknown_check_history" },
    puede_ejecutar: puedeEjecutar,
  };
}

async function actuar(referencia, accion) {
  const ruta = RUTAS[accion];
  if (!ruta) return sinCambios(false);
  let response;
  try {
    response = await fetch("/api/bandeja/" + encodeURIComponent(referencia) + "/" + ruta, {
      method: "POST",
      headers: cabeceras(),
    });
  } catch (_error) {
    return sinCambios(accion === "execute");
  }
  olvidarSiCaduco(response);
  let data = null;
  try {
    data = await response.json();
  } catch (_error) {
    data = null;
  }
  const conMensaje = data && data.mensaje && typeof data.mensaje.codigo === "string";
  if (!response.ok || !conMensaje || typeof data.situacion !== "string") {
    return {
      situacion: "unchanged",
      mensaje: conMensaje ? data.mensaje : { codigo: "outcome_unknown_check_history" },
      puede_ejecutar: false,
    };
  }
  return data;
}

function pintarSolicitud(solicitud) {
  const item = document.createElement("li");
  item.className = "solicitud";
  const situacion = document.createElement("strong");
  const datos = document.createElement("div");
  datos.className = "datos";
  const confirmacion = document.createElement("div");
  const acciones = document.createElement("div");
  acciones.className = "acciones";
  const resultado = document.createElement("p");
  resultado.className = "resultado";
  resultado.setAttribute("role", "status");

  // "decidir": the decision buttons; "confirmar": the summary and its
  // confirm button; "ocupado": a call is under way; "hecho": after acting.
  let fase = "decidir";
  let situacionCodigo = solicitud.situacion;
  let textoResultado = null;
  let puedeEjecutarDespues = false;

  function boton(clave, clase, alHacerClic) {
    const nuevo = document.createElement("button");
    nuevo.type = "button";
    if (clase) nuevo.className = clase;
    nuevo.textContent = t(clave);
    nuevo.addEventListener("click", alHacerClic);
    return nuevo;
  }

  function bloquear() {
    for (const cada of acciones.querySelectorAll("button")) cada.disabled = true;
  }

  function decirResultado(texto) {
    textoResultado = texto;
    resultado.textContent = texto ? texto() : "";
  }

  // The window, in local time and UTC, and the time left from this page's
  // clock: informational, the gateway decides with its own clock.
  function valeHasta() {
    const queda = tiempoRestante(solicitud.vale_hasta_utc, Date.now());
    return t("field.valid_until") + ": " + hora(solicitud.vale_hasta_utc, true) + " (" + t(queda.clave, { n: queda.n }) + ")";
  }

  // Texts come quoted from the console; a list shows each element apart.
  // Keys and values are shown as they are, in no language.
  function listaParametros() {
    const parametros = document.createElement("dl");
    parametros.className = "parametros";
    if (!solicitud.parametros_visibles) return parametros;
    if (!solicitud.parametros.length) parametros.append(linea(t("params.none")));
    for (const parametro of solicitud.parametros) {
      const clave = document.createElement("dt");
      clave.textContent = parametro.clave;
      const valor = document.createElement("dd");
      if (Array.isArray(parametro.lista)) {
        // A list never looks like a text: it says it is a list and how long,
        // and each element carries its own mark "[n]".
        valor.className = "es-lista";
        const cabecera = document.createElement("span");
        cabecera.className = "marca";
        cabecera.textContent = parametro.lista.length
          ? t("params.list", { n: parametro.lista.length })
          : t("params.empty_list");
        valor.append(cabecera);
        parametro.lista.forEach((elemento, indice) => {
          const fila = document.createElement("div");
          fila.className = "elemento";
          const marca = document.createElement("span");
          marca.className = "marca";
          marca.textContent = "[" + (indice + 1) + "] ";
          fila.append(marca, document.createTextNode(elemento));
          valor.append(fila);
        });
      } else {
        valor.textContent = parametro.valor;
      }
      parametros.append(clave, valor);
    }
    return parametros;
  }

  function pintarDatos() {
    situacion.textContent = t("situation." + situacionCodigo);
    const nota = document.createElement("p");
    nota.className = "nota";
    if (solicitud.nota) nota.textContent = mensaje(solicitud.nota, "message.parameters_not_shown");
    datos.replaceChildren(
      linea(etiquetaAgente(solicitud.agente)),
      linea(t("field.wants") + ": " + mostrado(solicitud.queria)),
      linea(t("field.on") + ": " + mostrado(solicitud.sobre)),
      listaParametros(),
      linea(valeHasta()),
      linea(t("field.requested") + ": " + hora(solicitud.pedida_utc, false)),
      nota,
    );
  }

  // One line per fact and per parameter, as in the card: nothing is joined
  // into a sentence where a comma or a colon could be read two ways.
  function resumen(pregunta) {
    const caja = document.createElement("div");
    caja.className = "confirmacion";
    const titulo = document.createElement("strong");
    titulo.textContent = pregunta;
    caja.append(
      titulo,
      linea(etiquetaAgente(solicitud.agente)),
      linea(t("field.wants") + ": " + mostrado(solicitud.queria)),
      linea(t("field.on") + ": " + mostrado(solicitud.sobre)),
      listaParametros(),
      linea(valeHasta()),
    );
    return caja;
  }

  function mostrar(data) {
    fase = "hecho";
    if (data.situacion !== "unchanged") situacionCodigo = data.situacion;
    puedeEjecutarDespues = Boolean(data.puede_ejecutar);
    situacion.textContent = t("situation." + situacionCodigo);
    decirResultado(() => mensaje(data.mensaje, "message.outcome_unknown_check_history"));
    pintarDespues();
  }

  function pintarDespues() {
    acciones.replaceChildren();
    if (puedeEjecutarDespues) acciones.append(boton("button.retry_execution", "aprobar", ejecutar));
  }

  async function ejecutar() {
    fase = "ocupado";
    bloquear();
    decirResultado(() => t("inbox.executing"));
    mostrar(await actuar(solicitud.referencia, "execute"));
  }

  // First click: the summary to confirm, in the same card. Second click:
  // the one signed decision.
  function confirmar(clavePregunta, claveBoton, alConfirmar) {
    fase = "confirmar";
    acciones.replaceChildren();
    decirResultado(null);
    confirmacion.replaceChildren(resumen(t(clavePregunta)));
    acciones.append(
      boton(claveBoton, "aprobar", alConfirmar),
      boton("button.cancel", "", cancelar),
    );
  }

  function cancelar() {
    confirmacion.replaceChildren();
    fase = "decidir";
    pintarDecision();
  }

  async function aprobarYEjecutar() {
    confirmacion.replaceChildren();
    fase = "ocupado";
    bloquear();
    decirResultado(() => t("inbox.approving"));
    const aprobado = await actuar(solicitud.referencia, "approve");
    mostrar(aprobado);
    if (!aprobado.puede_ejecutar) return;
    await ejecutar();
  }

  async function rechazar() {
    confirmacion.replaceChildren();
    fase = "ocupado";
    bloquear();
    decirResultado(() => t("inbox.rejecting"));
    mostrar(await actuar(solicitud.referencia, "reject"));
  }

  function pintarDecision() {
    acciones.replaceChildren();
    if (solicitud.puede_aprobar) {
      acciones.append(boton("button.approve_execute", "aprobar", () =>
        confirmar("confirm.approve_execute.question", "confirm.approve_execute.button", aprobarYEjecutar)));
    }
    if (solicitud.puede_rechazar) {
      acciones.append(boton("button.reject", "", () =>
        confirmar("confirm.reject.question", "confirm.reject.button", rechazar)));
    }
    if (solicitud.puede_ejecutar) acciones.append(boton("button.execute", "aprobar", ejecutar));
  }

  // A change of language words the card again. An open confirmation is
  // cancelled: nobody confirms a text other than the one they read.
  function repintar() {
    pintarDatos();
    resultado.textContent = textoResultado ? textoResultado() : "";
    if (fase === "confirmar") {
      cancelar();
    } else if (fase === "decidir") {
      pintarDecision();
    } else if (fase === "hecho") {
      pintarDespues();
    }
  }

  pintarDatos();
  pintarDecision();
  item.append(situacion, datos, confirmacion, acciones, resultado);
  return { item, repintar };
}

function pintarEstadoBandeja(data) {
  const partes = [t("inbox.waiting", { n: data.solicitudes.length })];
  if (data.vencidas) partes.push(t("inbox.expired", { n: data.vencidas }));
  if (data.hay_mas) partes.push(t("message.inbox_truncated", { limite: data.limite }));
  if (data.ilegibles) partes.push(t("inbox.unreadable", { n: data.ilegibles }));
  return partes.join(" · ");
}

async function cargarBandeja() {
  decir(bandejaEstado, () => t("inbox.loading"));
  let response;
  try {
    response = await fetch("/api/bandeja", { headers: cabeceras() });
  } catch (_error) {
    decir(bandejaEstado, () => t("inbox.read_failed"));
    return;
  }
  olvidarSiCaduco(response);
  let data = null;
  try {
    data = await response.json();
  } catch (_error) {
    data = null;
  }
  tarjetas = [];
  if (response.status === 401) {
    solicitudes.replaceChildren();
    decir(bandejaEstado, () => t("session.open_link"));
    return;
  }
  if (!response.ok || !data || !Array.isArray(data.solicitudes)) {
    solicitudes.replaceChildren();
    const recibido = data && data.mensaje;
    decir(bandejaEstado, () => mensaje(recibido, "inbox.read_failed"));
    return;
  }
  decir(bandejaAviso, () => t("notice." + data.aviso));
  solicitudes.replaceChildren();
  decir(bandejaEstado, () => pintarEstadoBandeja(data));
  if (!data.solicitudes.length) {
    const vacio = document.createElement("li");
    vacio.className = "vacio";
    const repintar = () => {
      vacio.textContent = t("inbox.empty");
    };
    repintar();
    tarjetas.push({ repintar });
    solicitudes.append(vacio);
    return;
  }
  for (const solicitud of data.solicitudes) {
    const tarjeta = pintarSolicitud(solicitud);
    tarjetas.push(tarjeta);
    solicitudes.append(tarjeta.item);
  }
}

async function descargarPaquete() {
  const boton = document.getElementById("descargar-paquete");
  const estadoPaquete = document.getElementById("paquete-estado");
  boton.disabled = true;
  decir(estadoPaquete, () => t("pack.building"));
  try {
    let response;
    try {
      response = await fetch("/api/paquete", {
        headers: cabeceras(),
      });
    } catch (_error) {
      decir(estadoPaquete, () => t("pack.request_failed"));
      return;
    }
    olvidarSiCaduco(response);
    if (response.status === 401) {
      decir(estadoPaquete, () => t("session.open_link"));
      return;
    }
    if (!response.ok) {
      let data = null;
      try {
        data = await response.json();
      } catch (_error) {
        data = null;
      }
      const recibido = data && data.mensaje;
      decir(estadoPaquete, () => mensaje(recibido, "message.pack_archive"));
      return;
    }
    const archivo = await response.blob();
    const enlace = document.createElement("a");
    enlace.href = URL.createObjectURL(archivo);
    enlace.download = "praetore-compliance.tar.gz";
    document.body.append(enlace);
    enlace.click();
    enlace.remove();
    setTimeout(() => URL.revokeObjectURL(enlace.href), 60000);
    decir(estadoPaquete, () => t("pack.downloaded"));
  } finally {
    boton.disabled = false;
  }
}

async function estadoPaquete() {
  const boton = document.getElementById("descargar-paquete");
  const estadoNodo = document.getElementById("paquete-estado");
  let data = null;
  try {
    const response = await fetch("/api/paquete/estado", { headers: cabeceras() });
    olvidarSiCaduco(response);
    if (response.ok) data = await response.json();
  } catch (_error) {
    data = null;
  }
  // Without an answer the button stays: the download itself says what failed.
  if (data && data.configurado === false) {
    boton.hidden = true;
    const recibido = data.mensaje;
    decir(estadoNodo, () => mensaje(recibido, "message.pack_off"));
  }
}

// A change of language: keep the choice, word the page again, and cancel any
// open confirmation (each card goes back to its decision buttons).
async function cambiarIdioma(valor) {
  if (!IDIOMAS.includes(valor)) return;
  guardarIdioma(valor);
  if (!(await usarIdioma(valor))) return;
  for (const [nodo, texto] of textos) nodo.textContent = texto();
  if (ultimaLista) pintarLista(ultimaLista);
  if (ultimoDetalle) pintarDetalle(ultimoDetalle);
  for (const tarjeta of tarjetas) tarjeta.repintar();
}

document.getElementById("idioma").addEventListener("change", (event) => {
  cambiarIdioma(event.target.value);
});

document.getElementById("descargar-paquete").addEventListener("click", descargarPaquete);

document.getElementById("recargar-bandeja").addEventListener("click", () => {
  cargarBandeja();
  cargar();
});

document.getElementById("filtros").addEventListener("submit", (event) => {
  event.preventDefault();
  pagina = 1;
  cargar();
});
document.getElementById("anterior").addEventListener("click", () => {
  if (pagina > 1) {
    pagina -= 1;
    cargar();
  }
});
document.getElementById("siguiente").addEventListener("click", () => {
  if (pagina < paginas) {
    pagina += 1;
    cargar();
  }
});

async function iniciar() {
  const elegido = elegirIdioma(idiomaGuardado(), navigator.languages);
  const pedidoInicial = ultimoPedidoDeIdioma + 1;
  const usado = await usarIdioma(elegido);
  // Spanish only when the chosen catalog failed, not when a newer choice superseded it.
  if (!usado && elegido !== "es" && ultimoPedidoDeIdioma === pedidoInicial) await usarIdioma("es");
  const codigo = codigoDelHash();
  if (codigo) {
    await abrirSesion(codigo);
    // Clear the fragment so the one-time code does not linger in the URL.
    history.replaceState(null, "", window.location.pathname + window.location.search);
  }
  if (!tokenSesion()) {
    decir(estado, () => t("session.open_link"));
    decir(bandejaEstado, () => "");
    return;
  }
  cargar();
  cargarBandeja();
  estadoPaquete();
}
iniciar();
