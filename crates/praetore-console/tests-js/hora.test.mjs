// How the page shows an instant: local time with its offset, and UTC
// beside it. Every case names its zone, so the result does not depend on
// the machine running the tests. Run: node --test crates/praetore-console/tests-js/
import { test } from "node:test";
import assert from "node:assert/strict";
import { desfase, formatearInstante, tiempoRestante } from "../ui/hora.js";

const SANTIAGO = "America/Santiago";

// "<local date>, HH:MM[:SS] (UTC±HH:MM) · YYYY-MM-DD HH:MM[:SS] UTC". The
// local date's words come from the browser's Intl; only the day and year
// are checked here, the rest of the line exactly.
function partes(texto) {
  const encontrado = /^(.+), (\d\d:\d\d(?::\d\d)?) \((UTC[+-]\d\d:\d\d)\) · (\d{4}-\d\d-\d\d \d\d:\d\d(?::\d\d)? UTC)$/.exec(texto);
  assert.ok(encontrado, texto);
  const [, dia, hora, desfaseLocal, utc] = encontrado;
  return { dia, hora, desfase: desfaseLocal, utc };
}

function diaLocal(texto, numero, anio) {
  const { dia } = partes(texto);
  assert.match(dia, new RegExp("(^|\\D)" + numero + "(\\D|$)"), texto);
  assert.match(dia, new RegExp(String(anio)), texto);
}

test("Santiago, clocks forward on 2026-09-06 04:00Z: 03:59Z is 23:59 on the 5th, 04:00Z is 01:00 on the 6th", () => {
  const antes = formatearInstante("2026-09-06T03:59:00Z", "es", SANTIAGO);
  const despues = formatearInstante("2026-09-06T04:00:00Z", "es", SANTIAGO);
  assert.deepEqual(
    { hora: partes(antes).hora, desfase: partes(antes).desfase, utc: partes(antes).utc },
    { hora: "23:59", desfase: "UTC-04:00", utc: "2026-09-06 03:59 UTC" },
  );
  diaLocal(antes, 5, 2026);
  assert.deepEqual(
    { hora: partes(despues).hora, desfase: partes(despues).desfase, utc: partes(despues).utc },
    { hora: "01:00", desfase: "UTC-03:00", utc: "2026-09-06 04:00 UTC" },
  );
  diaLocal(despues, 6, 2026);
});

test("Santiago, clocks back on 2026-04-05 03:00Z: 02:30Z and 03:30Z are both 23:30 on the 4th, and read differently", () => {
  const primera = formatearInstante("2026-04-05T02:30:00Z", "es", SANTIAGO);
  const segunda = formatearInstante("2026-04-05T03:30:00Z", "es", SANTIAGO);
  assert.equal(partes(primera).hora, "23:30");
  assert.equal(partes(segunda).hora, "23:30");
  diaLocal(primera, 4, 2026);
  diaLocal(segunda, 4, 2026);
  assert.equal(partes(primera).desfase, "UTC-03:00");
  assert.equal(partes(segunda).desfase, "UTC-04:00");
  assert.equal(partes(primera).utc, "2026-04-05 02:30 UTC");
  assert.equal(partes(segunda).utc, "2026-04-05 03:30 UTC");
  assert.notEqual(primera, segunda);
  for (const idioma of ["en", "pt"]) {
    assert.notEqual(
      formatearInstante("2026-04-05T02:30:00Z", idioma, SANTIAGO),
      formatearInstante("2026-04-05T03:30:00Z", idioma, SANTIAGO),
    );
  }
});

test("UTC: the local part is the UTC part, offset +00:00, seconds when asked", () => {
  const texto = formatearInstante("2026-11-13T06:53:07Z", "es", "UTC", { segundos: true });
  assert.deepEqual(
    { hora: partes(texto).hora, desfase: partes(texto).desfase, utc: partes(texto).utc },
    { hora: "06:53:07", desfase: "UTC+00:00", utc: "2026-11-13 06:53:07 UTC" },
  );
  diaLocal(texto, 13, 2026);
  const sin = formatearInstante("2026-11-13T06:53:07Z", "es", "UTC");
  assert.equal(partes(sin).hora, "06:53");
  assert.equal(partes(sin).utc, "2026-11-13 06:53 UTC");
});

test("Asia/Kolkata: a half-hour offset, and a local date ahead of the UTC date near midnight", () => {
  const texto = formatearInstante("2026-11-13T23:50:00Z", "es", "Asia/Kolkata");
  assert.equal(partes(texto).hora, "05:20");
  assert.equal(partes(texto).desfase, "UTC+05:30");
  assert.equal(partes(texto).utc, "2026-11-13 23:50 UTC");
  diaLocal(texto, 14, 2026);
});

test("near midnight the local date is behind the UTC date in Santiago", () => {
  const texto = formatearInstante("2026-11-13T02:10:00Z", "es", SANTIAGO);
  assert.equal(partes(texto).hora, "23:10");
  assert.equal(partes(texto).desfase, "UTC-03:00");
  assert.equal(partes(texto).utc, "2026-11-13 02:10 UTC");
  diaLocal(texto, 12, 2026);
});

test("es, en and pt give the same UTC part, in every zone", () => {
  for (const zona of [SANTIAGO, "UTC", "Asia/Kolkata", "Europe/Lisbon", "Pacific/Chatham"]) {
    for (const instante of ["2026-09-06T03:59:59Z", "2026-04-05T03:30:00Z", "2026-12-31T23:59:59Z"]) {
      const utc = ["es", "en", "pt"].map((idioma) => partes(formatearInstante(instante, idioma, zona, { segundos: true })).utc);
      assert.equal(utc[0], utc[1], zona + " " + instante);
      assert.equal(utc[0], utc[2], zona + " " + instante);
      const horas = ["es", "en", "pt"].map((idioma) => partes(formatearInstante(instante, idioma, zona, { segundos: true })).hora);
      assert.equal(new Set(horas).size, 1, zona + " " + instante);
    }
  }
  assert.equal(partes(formatearInstante("2026-12-31T23:59:59Z", "en", "UTC", { segundos: true })).utc, "2026-12-31 23:59:59 UTC");
});

test("the date is in the page's language", () => {
  const es = partes(formatearInstante("2026-09-06T12:00:00Z", "es", "UTC")).dia;
  const en = partes(formatearInstante("2026-09-06T12:00:00Z", "en", "UTC")).dia;
  const pt = partes(formatearInstante("2026-09-06T12:00:00Z", "pt", "UTC")).dia;
  assert.match(en, /Sep/);
  assert.notEqual(es, en);
  assert.notEqual(pt, en);
});

test("seconds are cut, never rounded; a bad instant shows a dash", () => {
  const texto = formatearInstante("2026-11-13T06:53:07.999Z", "es", "UTC", { segundos: true });
  assert.equal(partes(texto).hora, "06:53:07");
  assert.equal(partes(texto).utc, "2026-11-13 06:53:07 UTC");
  const conDesfase = formatearInstante("2026-11-13T03:53:07-03:00", "es", "UTC", { segundos: true });
  assert.equal(partes(conDesfase).utc, "2026-11-13 06:53:07 UTC");
  for (const malo of ["", "ayer", null, undefined, 5]) {
    assert.equal(formatearInstante(malo, "es", "UTC"), "—");
  }
});

test("offsets are written with sign, hours and minutes", () => {
  assert.equal(desfase(0), "UTC+00:00");
  assert.equal(desfase(-180), "UTC-03:00");
  assert.equal(desfase(330), "UTC+05:30");
  assert.equal(desfase(-570), "UTC-09:30");
  assert.equal(desfase(765), "UTC+12:45");
});

test("the time left is counted from the page's clock, informational only", () => {
  const hasta = "2026-11-13T12:00:00Z";
  const en = (segundos) => Date.parse(hasta) - segundos * 1000;
  assert.deepEqual(tiempoRestante(hasta, en(0)), { clave: "time_left.closed", n: 0 });
  assert.deepEqual(tiempoRestante(hasta, en(-5)), { clave: "time_left.closed", n: 0 });
  assert.deepEqual(tiempoRestante(hasta, en(59)), { clave: "time_left.under_minute", n: 0 });
  assert.deepEqual(tiempoRestante(hasta, en(60)), { clave: "time_left.minutes", n: 1 });
  assert.deepEqual(tiempoRestante(hasta, en(3599)), { clave: "time_left.minutes", n: 59 });
  assert.deepEqual(tiempoRestante(hasta, en(3600)), { clave: "time_left.hours", n: 1 });
  assert.deepEqual(tiempoRestante(hasta, en(7300)), { clave: "time_left.hours", n: 2 });
  assert.deepEqual(tiempoRestante("no", en(100)), { clave: "time_left.closed", n: 0 });
});
