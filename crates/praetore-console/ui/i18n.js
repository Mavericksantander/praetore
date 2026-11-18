// Languages of the page. Presentation only: the console signs, records and
// exports the same bytes whatever the operator reads the page in.

export const IDIOMAS = Object.freeze(["es", "en", "pt"]);
export const IDIOMA_POR_DEFECTO = "es";

// The operator's choice, kept in this browser. Not a secret.
export const LLAVE_IDIOMA = "praetore_idioma";

// Locale each language uses for Intl (dates, plurals).
export const LOCALES = Object.freeze({ es: "es", en: "en", pt: "pt-BR" });

// The language to show: the saved choice when it is one of IDIOMAS, else the
// first browser language whose prefix is one of them (pt-BR and pt-PT give
// pt, en-US gives en), else Spanish. Pure: it reads nothing else.
export function elegirIdioma(guardado, idiomasNavegador) {
  if (typeof guardado === "string" && IDIOMAS.includes(guardado)) return guardado;
  for (const etiqueta of Array.isArray(idiomasNavegador) ? idiomasNavegador : []) {
    if (typeof etiqueta !== "string") continue;
    const prefijo = etiqueta.trim().toLowerCase().split("-")[0];
    if (IDIOMAS.includes(prefijo)) return prefijo;
  }
  return IDIOMA_POR_DEFECTO;
}

// A translator over one catalog: t(clave, parametros). A value that is an
// object holds plural forms, chosen with Intl.PluralRules on `n`; `{name}`
// is replaced by parametros.name. A missing key shows itself, so a gap is
// visible instead of silent.
export function crearTraductor(catalogo, idioma) {
  const reglas = new Intl.PluralRules(LOCALES[idioma] || LOCALES[IDIOMA_POR_DEFECTO]);
  const fuente = catalogo && typeof catalogo === "object" ? catalogo : {};
  return function t(clave, parametros) {
    let texto = Object.prototype.hasOwnProperty.call(fuente, clave) ? fuente[clave] : undefined;
    if (texto && typeof texto === "object") {
      const n = parametros && typeof parametros.n === "number" ? parametros.n : 0;
      texto = texto[reglas.select(n)] ?? texto.other;
    }
    if (typeof texto !== "string") return clave;
    return texto.replace(/\{([a-z_]+)\}/g, (marca, nombre) =>
      parametros && Object.prototype.hasOwnProperty.call(parametros, nombre)
        ? String(parametros[nombre])
        : marca,
    );
  };
}
