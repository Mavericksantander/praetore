//! `docs/security/evasion-matrix.md` renders as tables only if each table's
//! second line is its `|---|` separator. A row inserted between the header
//! and the separator turns the whole table into plain text; this test reads
//! the file and refuses that.

/// One message per table whose second line is not a separator with the
/// header's column count, or that has a separator anywhere else.
fn table_errors(text: &str) -> Vec<String> {
    let is_separator = |line: &str| {
        let inner = line.trim().trim_matches('|');
        !inner.is_empty()
            && inner.split('|').all(|cell| {
                !cell.trim().is_empty() && cell.trim().chars().all(|c| matches!(c, '-' | ':'))
            })
    };
    let columns = |line: &str| line.trim().trim_matches('|').split('|').count();
    let mut errors = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut at = 0;
    while at < lines.len() {
        if !lines[at].starts_with('|') {
            at += 1;
            continue;
        }
        let start = at;
        while at < lines.len() && lines[at].starts_with('|') {
            at += 1;
        }
        let table = &lines[start..at];
        let header = start + 1;
        match table.get(1) {
            Some(second) if is_separator(second) && columns(second) == columns(table[0]) => {}
            _ => errors.push(format!(
                "line {header}: the table's second line is not its |---| separator"
            )),
        }
        for (offset, line) in table.iter().enumerate().skip(2) {
            if is_separator(line) {
                errors.push(format!(
                    "line {}: a separator inside the table",
                    start + offset + 1
                ));
            }
        }
    }
    errors
}

#[test]
fn every_table_in_the_evasion_matrix_has_its_separator_second() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/security/evasion-matrix.md"
    );
    let text = std::fs::read_to_string(path).unwrap();
    assert!(
        text.contains("| Defence removed | Test that fails |"),
        "{path}"
    );
    let errors = table_errors(&text);
    assert!(errors.is_empty(), "{path}: {errors:?}");
}

#[test]
fn a_row_between_the_header_and_the_separator_is_an_error() {
    let broken = "text\n\n| A | B |\n| row | here |\n|---|---|\n| x | y |\n";
    assert_eq!(table_errors(broken).len(), 2, "{:?}", table_errors(broken));
    let fine = "| A | B |\n|---|:---:|\n| row | here |\n";
    assert!(table_errors(fine).is_empty(), "{:?}", table_errors(fine));
}
