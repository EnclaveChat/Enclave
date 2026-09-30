//! Generates the design tokens and compiles the Slint UI.
#![allow(clippy::expect_used, clippy::panic)]

fn main() {
    let tokens_path = "../../design/tokens.toml";
    println!("cargo:rerun-if-changed={tokens_path}");
    let text = std::fs::read_to_string(tokens_path).expect("design/tokens.toml");
    let tokens = enclave_design::Tokens::parse(&text).expect("valid tokens");
    let failures = tokens
        .check()
        .expect("contrast pairs reference known tokens");
    assert!(failures.is_empty(), "contrast failures: {failures:#?}");
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(out.join("tokens.slint"), tokens.to_slint().expect("tokens"))
        .expect("write tokens.slint");
    let config = slint_build::CompilerConfiguration::new().with_include_paths(vec![out]);
    slint_build::compile_with_config("ui/app.slint", config).expect("Slint UI compiles");
}
