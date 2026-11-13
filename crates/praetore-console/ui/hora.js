// How the page shows an instant: the local time of the browser's zone, with
// its offset, and the UTC time beside it, for example
//   "13 nov 2026, 03:53 (UTC-03:00) · 2026-11-13 06:53 UTC".
// The offset tells apart the hour that repeats when the clocks go back. The
// UTC part is built here from the instant alone: it is the same in every
// language and every zone. Pure: the instant, the language and the zone are
// parameters, so it is tested without the machine's zone or clock.

import { IDIOMA_POR_DEFECTO, LOCALES } from "./i18n.js";

function dosCifras(numero) {
  return String(numero).padStart(2, "0");
}

// Wall-clock fields of `fecha` in `zona`, as numbers.
function camposLocales(fecha, zona) {
  const partes = new Intl.DateTimeFormat("en-US", {
    timeZone: zona,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  }).formatToParts(fecha);
  const valor = (tipo) => Number(partes.find((parte) => parte.type === tipo).value);
  return {
    anio: valor("year"),
    mes: valor("month"),
    dia: valor("day"),
    // Some engines say 24 for midnight.
    hora: valor("hour") % 24,
    minuto: valor("minute"),
    segundo: valor("second"),
  };
}

// "UTC-03:00", "UTC+05:30", "UTC+00:00".
export function desfase(minutos) {
  const signo = minutos < 0 ? "-" : "+";
  const absoluto = Math.abs(minutos);
  return "UTC" + signo + dosCifras(Math.floor(absoluto / 60)) + ":" + dosCifras(absoluto % 60);
}

// `iso`: RFC 3339 from the console. `segundos`: show seconds (deadlines).
export function formatearInstante(iso, idioma, zona, opciones) {
  const segundos = Boolean(opciones && opciones.segundos);
  const fecha = new Date(iso);
  if (typeof iso !== "string" || Number.isNaN(fecha.getTime())) return "—";
  // Whole seconds: what is shown is what the offset is computed from.
  const instante = Math.floor(fecha.getTime() / 1000) * 1000;
  const exacta = new Date(instante);
  const local = camposLocales(exacta, zona);
  const comoUtc = Date.UTC(local.anio, local.mes - 1, local.dia, local.hora, local.minuto, local.segundo);
  const minutosDesfase = Math.round((comoUtc - instante) / 60000);
  const dia = new Intl.DateTimeFormat(LOCALES[idioma] || LOCALES[IDIOMA_POR_DEFECTO], {
    timeZone: zona,
    day: "numeric",
    month: "short",
    year: "numeric",
  }).format(exacta);
  const horaLocal =
    dosCifras(local.hora) + ":" + dosCifras(local.minuto) + (segundos ? ":" + dosCifras(local.segundo) : "");
  const utc =
    exacta.getUTCFullYear() +
    "-" +
    dosCifras(exacta.getUTCMonth() + 1) +
    "-" +
    dosCifras(exacta.getUTCDate()) +
    " " +
    dosCifras(exacta.getUTCHours()) +
    ":" +
    dosCifras(exacta.getUTCMinutes()) +
    (segundos ? ":" + dosCifras(exacta.getUTCSeconds()) : "") +
    " UTC";
  return dia + ", " + horaLocal + " (" + desfase(minutosDesfase) + ") · " + utc;
}

// The time left until `hastaIso`, from the page's clock (`ahoraMs`): a
// catalog key and its count. Informational only: the gateway decides with
// its own clock whether the window is still open.
export function tiempoRestante(hastaIso, ahoraMs) {
  const hasta = new Date(hastaIso).getTime();
  if (Number.isNaN(hasta)) return { clave: "time_left.closed", n: 0 };
  const segundos = Math.floor((hasta - ahoraMs) / 1000);
  if (segundos <= 0) return { clave: "time_left.closed", n: 0 };
  if (segundos < 60) return { clave: "time_left.under_minute", n: 0 };
  if (segundos < 3600) return { clave: "time_left.minutes", n: Math.floor(segundos / 60) };
  return { clave: "time_left.hours", n: Math.floor(segundos / 3600) };
}
