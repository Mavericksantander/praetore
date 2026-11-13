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

const estado = document.getElementById("estado");
const aviso = document.getElementById("aviso");
const lista = document.getElementById("lista");
const detalle = document.getElementById("detalle");
const paginaTexto = document.getElementById("pagina");
let pagina = 1;
let paginas = 1;

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
  paginaTexto.textContent = "Página " + data.pagina;
  document.getElementById("anterior").disabled = data.pagina <= 1;
  document.getElementById("siguiente").disabled = data.pagina >= data.paginas;
  if (!data.recibos.length) {
    const vacio = document.createElement("li");
    vacio.className = "vacio";
    vacio.textContent = "No hay recibos con ese criterio.";
    lista.append(vacio);
    return;
  }
  for (const recibo of data.recibos) {
    const item = document.createElement("li");
    const boton = document.createElement("button");
    boton.type = "button";
    boton.className = "recibo";
    const situacion = document.createElement("strong");
    situacion.textContent = recibo.situacion;
    const cuando = document.createElement("span");
    cuando.textContent = recibo.cuando;
    const agente = document.createElement("span");
    agente.textContent = recibo.agente;
    const queria = document.createElement("span");
    queria.textContent = "Quería hacer: " + recibo.queria;
    const sobre = document.createElement("span");
    sobre.textContent = "Sobre: " + recibo.sobre;
    boton.append(situacion, cuando, agente, queria, sobre);
    boton.addEventListener("click", () => abrir(recibo.abrir));
    item.append(boton);
    lista.append(item);
  }
}

async function cargar() {
  estado.textContent = "Leyendo el registro…";
  detalle.classList.add("hidden");
  const parametros = consulta();
  parametros.set("pagina", String(pagina));
  let response;
  try {
    response = await fetch("/api/historial?" + parametros.toString(), { headers: cabeceras() });
  } catch (_error) {
    estado.textContent = "No se pudo leer el registro.";
    return;
  }
  olvidarSiCaduco(response);
  if (response.status === 401) {
    estado.textContent = "Abre el enlace que la consola muestra en su terminal (vale una vez y 5 minutos). Si ya venció o se usó, pulsa Enter en esa terminal para otro, o reinicia la consola.";
    return;
  }
  if (!response.ok) {
    estado.textContent = "No se pudo leer el registro.";
    return;
  }
  const data = await response.json();
  aviso.textContent = data.aviso;
  paginas = data.paginas || 1;
  const cuantos = data.total === 1 ? "1 recibo" : data.total + " recibos";
  estado.textContent = cuantos;
  pintarLista(data);
}

async function abrir(numero) {
  const parametros = consulta();
  let response;
  try {
    response = await fetch("/api/historial/" + numero + "?" + parametros.toString(), {
      headers: cabeceras(),
    });
  } catch (_error) {
    estado.textContent = "No se pudo abrir el recibo.";
    return;
  }
  olvidarSiCaduco(response);
  if (!response.ok) {
    estado.textContent = "No se pudo abrir el recibo.";
    return;
  }
  const data = await response.json();
  detalle.classList.remove("hidden");
  detalle.replaceChildren();
  const titulo = document.createElement("h2");
  titulo.textContent = data.situacion;
  const grilla = document.createElement("div");
  grilla.className = "detail-grid";
  grilla.append(
    campo("Cuándo", data.cuando),
    campo("Actualizado", data.actualizado),
    campo("Agente", data.agente),
    campo("Quería hacer", data.queria),
    campo("Sobre", data.sobre),
  );
  const relato = document.createElement("p");
  relato.textContent = data.relato;
  const nota = document.createElement("p");
  nota.className = "aviso";
  nota.textContent = data.aviso;
  detalle.append(titulo, grilla, relato, nota);
  detalle.scrollIntoView({ block: "nearest" });
}

const bandejaEstado = document.getElementById("bandeja-estado");
const bandejaAviso = document.getElementById("bandeja-aviso");
const solicitudes = document.getElementById("solicitudes");

function linea(texto) {
  const span = document.createElement("span");
  span.textContent = texto;
  return span;
}

async function actuar(referencia, accion) {
  let response;
  try {
    response = await fetch("/api/bandeja/" + encodeURIComponent(referencia) + "/" + accion, {
      method: "POST",
      headers: cabeceras(),
    });
  } catch (_error) {
    return { situacion: "sin cambios", mensaje: "No se pudo confirmar qué pasó. Revisa el historial antes de seguir.", puede_ejecutar: accion === "ejecutar" };
  }
  olvidarSiCaduco(response);
  let data = null;
  try {
    data = await response.json();
  } catch (_error) {
    data = null;
  }
  if (!response.ok || !data || typeof data.mensaje !== "string") {
    return {
      situacion: "sin cambios",
      mensaje: data && typeof data.mensaje === "string" ? data.mensaje : "No se pudo confirmar qué pasó. Revisa el historial antes de seguir.",
      puede_ejecutar: false,
    };
  }
  return data;
}

function pintarSolicitud(solicitud) {
  const item = document.createElement("li");
  item.className = "solicitud";
  const situacion = document.createElement("strong");
  situacion.textContent = solicitud.situacion;
  const resultado = document.createElement("p");
  resultado.className = "resultado";
  resultado.setAttribute("role", "status");
  const acciones = document.createElement("div");
  acciones.className = "acciones";

  function boton(texto, clase, alHacerClic) {
    const nuevo = document.createElement("button");
    nuevo.type = "button";
    if (clase) nuevo.className = clase;
    nuevo.textContent = texto;
    nuevo.addEventListener("click", alHacerClic);
    return nuevo;
  }

  function bloquear() {
    for (const cada of acciones.querySelectorAll("button")) cada.disabled = true;
  }

  function mostrar(data) {
    if (data.situacion !== "sin cambios") situacion.textContent = data.situacion;
    resultado.textContent = data.mensaje;
    acciones.replaceChildren();
    if (data.puede_ejecutar) acciones.append(botonEjecutar("Reintentar ejecución"));
  }

  async function ejecutar() {
    bloquear();
    resultado.textContent = "Ejecutando…";
    mostrar(await actuar(solicitud.referencia, "ejecutar"));
  }

  function botonEjecutar(texto) {
    return boton(texto, "aprobar", ejecutar);
  }

  // First click: the summary to confirm, in the same card. Second click:
  // the one signed decision.
  function confirmar(pregunta, textoConfirmar, alConfirmar) {
    acciones.replaceChildren();
    resultado.textContent = "";
    confirmacion.replaceChildren(resumen(pregunta));
    acciones.append(
      boton(textoConfirmar, "aprobar", alConfirmar),
      boton("Cancelar", "", () => {
        confirmacion.replaceChildren();
        pintarDecision();
      }),
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
      linea(solicitud.agente),
      linea("Quiere hacer: " + solicitud.queria),
      linea("Sobre: " + solicitud.sobre),
      listaParametros(),
      linea("Vale hasta: " + solicitud.vale_hasta + " (" + solicitud.queda + ")"),
    );
    return caja;
  }

  async function aprobarYEjecutar() {
    confirmacion.replaceChildren();
    bloquear();
    resultado.textContent = "Aprobando…";
    const aprobado = await actuar(solicitud.referencia, "aprobar");
    mostrar(aprobado);
    if (!aprobado.puede_ejecutar) return;
    await ejecutar();
  }

  async function rechazar() {
    confirmacion.replaceChildren();
    bloquear();
    resultado.textContent = "Rechazando…";
    mostrar(await actuar(solicitud.referencia, "rechazar"));
  }

  function pintarDecision() {
    acciones.replaceChildren();
    if (solicitud.puede_aprobar) {
      acciones.append(boton("Aprobar y ejecutar", "aprobar", () =>
        confirmar("¿Aprobar y ejecutar?", "Confirmar: aprobar y ejecutar", aprobarYEjecutar)));
    }
    if (solicitud.puede_rechazar) {
      acciones.append(boton("Rechazar", "", () =>
        confirmar("¿Rechazar? Es final.", "Confirmar: rechazar", rechazar)));
    }
    if (solicitud.puede_ejecutar) acciones.append(botonEjecutar("Ejecutar"));
  }

  // Texts come quoted from the console; a list shows each element apart.
  function listaParametros() {
    const parametros = document.createElement("dl");
    parametros.className = "parametros";
    if (!solicitud.parametros_visibles) return parametros;
    if (!solicitud.parametros.length) parametros.append(linea("Sin parámetros"));
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
          ? "lista de " + parametro.lista.length + (parametro.lista.length === 1 ? " elemento:" : " elementos:")
          : "lista vacía []";
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

  const confirmacion = document.createElement("div");
  const nota = document.createElement("p");
  nota.className = "nota";
  if (solicitud.nota) nota.textContent = solicitud.nota;

  pintarDecision();
  item.append(
    situacion,
    linea(solicitud.agente),
    linea("Quiere hacer: " + solicitud.queria),
    linea("Sobre: " + solicitud.sobre),
    listaParametros(),
    linea("Vale hasta: " + solicitud.vale_hasta + " (" + solicitud.queda + ")"),
    linea("Pedida: " + solicitud.pedida),
    nota,
    confirmacion,
    acciones,
    resultado,
  );
  return item;
}

async function cargarBandeja() {
  bandejaEstado.textContent = "Leyendo la bandeja…";
  let response;
  try {
    response = await fetch("/api/bandeja", { headers: cabeceras() });
  } catch (_error) {
    bandejaEstado.textContent = "No se pudo leer la bandeja.";
    return;
  }
  olvidarSiCaduco(response);
  let data = null;
  try {
    data = await response.json();
  } catch (_error) {
    data = null;
  }
  if (response.status === 401) {
    solicitudes.replaceChildren();
    bandejaEstado.textContent = "Abre el enlace que la consola muestra en su terminal (vale una vez y 5 minutos). Si ya venció o se usó, pulsa Enter en esa terminal para otro, o reinicia la consola.";
    return;
  }
  if (!response.ok || !data) {
    solicitudes.replaceChildren();
    bandejaEstado.textContent = data && typeof data.mensaje === "string" ? data.mensaje : "No se pudo leer la bandeja.";
    return;
  }
  bandejaAviso.textContent = data.aviso;
  solicitudes.replaceChildren();
  const partes = [];
  partes.push(data.solicitudes.length === 1 ? "1 solicitud espera" : data.solicitudes.length + " solicitudes esperan");
  if (data.vencidas) partes.push(data.vencidas === 1 ? "1 venció sin decisión" : data.vencidas + " vencieron sin decisión");
  if (data.hay_mas) partes.push("hay más esperando: se muestran las 200 más recientes");
  if (data.ilegibles) partes.push(data.ilegibles === 1 ? "1 no se puede leer y no se ofrece" : data.ilegibles + " no se pueden leer y no se ofrecen");
  bandejaEstado.textContent = partes.join(" · ");
  if (!data.solicitudes.length) {
    const vacio = document.createElement("li");
    vacio.className = "vacio";
    vacio.textContent = "Nada espera una decisión.";
    solicitudes.append(vacio);
    return;
  }
  for (const solicitud of data.solicitudes) solicitudes.append(pintarSolicitud(solicitud));
}

async function descargarPaquete() {
  const boton = document.getElementById("descargar-paquete");
  const estadoPaquete = document.getElementById("paquete-estado");
  boton.disabled = true;
  estadoPaquete.textContent = "Armando el paquete…";
  try {
    let response;
    try {
      response = await fetch("/api/paquete", {
        headers: cabeceras(),
      });
    } catch (_error) {
      estadoPaquete.textContent = "No se pudo pedir el paquete.";
      return;
    }
    olvidarSiCaduco(response);
    if (response.status === 401) {
      estadoPaquete.textContent = "Abre el enlace que la consola muestra en su terminal (vale una vez y 5 minutos). Si ya venció o se usó, pulsa Enter en esa terminal para otro, o reinicia la consola.";
      return;
    }
    if (!response.ok) {
      let data = null;
      try {
        data = await response.json();
      } catch (_error) {
        data = null;
      }
      estadoPaquete.textContent = data && typeof data.mensaje === "string" ? data.mensaje : "No se pudo armar el paquete. No se generó ningún paquete.";
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
    estadoPaquete.textContent = "Paquete descargado: praetore-compliance.tar.gz. Las instrucciones para verificarlo están en LEEME.txt, dentro del paquete.";
  } finally {
    boton.disabled = false;
  }
}

async function estadoPaquete() {
  const boton = document.getElementById("descargar-paquete");
  const estado = document.getElementById("paquete-estado");
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
    estado.textContent = typeof data.mensaje === "string" ? data.mensaje : "El paquete de compliance no está configurado en esta consola.";
  }
}

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
  const codigo = codigoDelHash();
  if (codigo) {
    await abrirSesion(codigo);
    // Clear the fragment so the one-time code does not linger in the URL.
    history.replaceState(null, "", window.location.pathname + window.location.search);
  }
  if (!tokenSesion()) {
    estado.textContent = "Abre el enlace que la consola muestra en su terminal (vale una vez y 5 minutos). Si ya venció o se usó, pulsa Enter en esa terminal para otro, o reinicia la consola.";
    bandejaEstado.textContent = "";
    return;
  }
  cargar();
  cargarBandeja();
  estadoPaquete();
}
iniciar();
