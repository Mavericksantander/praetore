// The language the page chooses, and the translator over a catalog.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { crearTraductor, elegirIdioma } from "../ui/i18n.js";

function catalogo(idioma) {
  return JSON.parse(readFileSync(new URL("../ui/i18n/" + idioma + ".json", import.meta.url), "utf8"));
}

test("the saved choice, then the browser's languages, then Spanish", () => {
  assert.equal(elegirIdioma(null, ["pt-PT", "en"]), "pt");
  assert.equal(elegirIdioma(null, ["de-DE", "en-GB"]), "en");
  assert.equal(elegirIdioma(null, ["de-DE"]), "es");
  assert.equal(elegirIdioma("en", ["pt-BR"]), "en");
  assert.equal(elegirIdioma("xx", ["pt-BR"]), "pt");
  assert.equal(elegirIdioma("xx", ["de-DE"]), "es");
});

test("odd inputs fall back without failing", () => {
  assert.equal(elegirIdioma(undefined, undefined), "es");
  assert.equal(elegirIdioma("", []), "es");
  assert.equal(elegirIdioma("EN", ["fr"]), "es");
  assert.equal(elegirIdioma("pt-BR", ["fr"]), "es");
  assert.equal(elegirIdioma(null, [5, null, " EN-us "]), "en");
  assert.equal(elegirIdioma(null, "en"), "es");
  assert.equal(elegirIdioma(null, ["es-CL"]), "es");
  assert.equal(elegirIdioma(null, ["pt"]), "pt");
});

test("plurals follow each language's rules", () => {
  const es = crearTraductor(catalogo("es"), "es");
  const en = crearTraductor(catalogo("en"), "en");
  const pt = crearTraductor(catalogo("pt"), "pt");
  for (const t of [es, en, pt]) {
    const uno = t("history.count", { n: 1 });
    const varios = t("history.count", { n: 5 });
    assert.match(uno, /\b1\b/);
    assert.match(varios, /\b5\b/);
    assert.notEqual(uno.replace("1", ""), varios.replace("5", ""));
  }
  assert.equal(es("history.count", { n: 1 }), "1 recibo");
  assert.equal(es("history.count", { n: 0 }), "0 recibos");
  assert.equal(en("history.count", { n: 1 }), "1 receipt");
  // A form the catalog lacks (Spanish "many" for a million) falls back to "other".
  assert.match(es("history.count", { n: 1000000 }), /^1000000 /);
});

test("markers are filled, unknown ones stay, a missing key shows itself", () => {
  const t = crearTraductor({ a: "hola {nombre} {otro}" }, "es");
  assert.equal(t("a", { nombre: "<b>" }), "hola <b> {otro}");
  assert.equal(t("falta"), "falta");
  assert.equal(t("constructor"), "constructor");
  assert.equal(crearTraductor(null, "zz")("a"), "a");
});
