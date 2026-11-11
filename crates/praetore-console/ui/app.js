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
    response = await fetch("/api/historial?" + parametros.toString(), { credentials: "same-origin" });
  } catch (_error) {
    estado.textContent = "No se pudo leer el registro.";
    return;
  }
  if (response.status === 401) {
    estado.textContent = "No se pudo abrir la sesión local. Vuelve a cargar la página.";
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
      credentials: "same-origin",
    });
  } catch (_error) {
    estado.textContent = "No se pudo abrir el recibo.";
    return;
  }
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
cargar();
