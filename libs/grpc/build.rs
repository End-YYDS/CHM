use std::env;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let p_crate = Path::new(&env::var("CARGO_MANIFEST_DIR")?).to_owned();
    let generated = p_crate.join("src/generated");
    if !generated.exists() {
        std::fs::create_dir_all(&generated)?;
    }
    let proto_root = p_crate.join("proto_def");
    let mut protos = Vec::new();
    if env::var("CARGO_FEATURE_CA").is_ok() {
        protos.push(proto_root.join("ca.proto"));
    }
    // if env::var("CARGO_FEATURE_{features_name}").is_ok() {
    //     protos.push(proto_root.join("{file_name}.proto"));
    // }

    if protos.is_empty() {
        println!("cargo:warning=No proto features enabled, skipping tonic-build");
        return Ok(());
    }

    let proto_strs: Vec<_> = protos
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir(&generated)
        .compile_protos(&proto_strs, &[proto_root])?;
    let mut mod_rs = String::new();
    for entry in std::fs::read_dir(&generated)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            if let Some(name) = path.file_stem().and_then(|n| n.to_str()) {
                if name != "mod" {
                    mod_rs += &format!("#[cfg(feature = \"{0}\")]\n", name);
                    mod_rs += &format!("pub mod {};\n\n", name);
                }
            }
        }
    }
    std::fs::write(generated.join("mod.rs"), mod_rs)?;
    Ok(())
}
