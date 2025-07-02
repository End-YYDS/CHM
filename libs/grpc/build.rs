use std::path::Path;
use std::{env, fs};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let crate_root = Path::new(&env::var("CARGO_MANIFEST_DIR")?).to_owned();
    let out_dir = crate_root.join("src/generated");
    if !out_dir.exists() {
        fs::create_dir_all(&out_dir)?;
    }
    let proto_root = crate_root.join("proto_def");
    for entry in fs::read_dir(&proto_root)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("proto") {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("檔名一定要是 valid UTF-8");
        let feature_client = format!("CARGO_FEATURE_{}_CLIENT", stem.to_uppercase());
        let feature_server = format!("CARGO_FEATURE_{}_SERVER", stem.to_uppercase());
        if env::var(&feature_client).is_err() && env::var(&feature_server).is_err() {
            continue;
        }
        let want_client = env::var(&feature_client).is_ok();
        let want_server = env::var(&feature_server).is_ok();
        tonic_build::configure()
            .out_dir(&out_dir)
            .client_mod_attribute(stem, format!("#[cfg(feature = \"{stem}-client\")]"))
            .server_mod_attribute(stem, format!("#[cfg(feature = \"{stem}-server\")]"))
            .build_client(want_client)
            .build_server(want_server)
            .compile_protos(&[path.clone()], &[&proto_root])?;
    }
    let mut mod_rs = String::new();
    for entry in fs::read_dir(&proto_root)? {
        let p = entry?.path();
        if p.extension().and_then(|e| e.to_str()) != Some("proto") {
            continue;
        }
        let stem = p.file_stem().unwrap().to_str().unwrap();
        mod_rs +=
            &format!("#[cfg(any(feature = \"{stem}-client\", feature = \"{stem}-server\"))]\n",);
        mod_rs += &format!("pub mod {stem};\n\n",);
    }
    fs::write(out_dir.join("mod.rs"), mod_rs)?;

    Ok(())
}
