// `extension-module` deja los símbolos `_Py*` sin resolver: los aporta el
// intérprete al importar el módulo. El linker de Linux lo acepta en una
// cdylib, pero el de macOS exige `-undefined dynamic_lookup` (#57). Esta
// llamada agrega esos argumentos solo en Darwin; en otros targets no hace nada.
fn main() {
    pyo3_build_config::add_extension_module_link_args();
}
