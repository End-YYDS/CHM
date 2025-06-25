// use std::env;
// use std::path::Path;

// fn main() -> Result<(), Box<dyn std::error::Error>> {
//     let p_crate = Path::new(&env::var("CARGO_MANIFEST_DIR")?).to_owned();
//     let generated = p_crate.join("src/generated");
//     if !generated.exists() {
//         std::fs::create_dir_all(&generated)?;
//     }
//     let proto_root = p_crate.join("proto_def");
//     let mut protos = Vec::new();
//     if env::var("CARGO_FEATURE_CA").is_ok() {
//         protos.push(proto_root.join("ca.proto"));
//     }
//     if env::var("CARGO_FEATURE_CRL").is_ok() {
//         protos.push(proto_root.join("crl.proto"));
//     }
//     // if env::var("CARGO_FEATURE_{features_name}").is_ok() {
//     //     protos.push(proto_root.join("{file_name}.proto"));
//     // }

//     if protos.is_empty() {
//         println!("cargo:warning=No proto features enabled, skipping tonic-build");
//         return Ok(());
//     }

//     let proto_strs: Vec<_> = protos
//         .iter()
//         .map(|p| p.to_string_lossy().into_owned())
//         .collect();

//     tonic_build::configure()
//         .build_server(true)
//         .build_client(true)
//         .out_dir(&generated)
//         .compile_protos(&proto_strs, &[proto_root])?;
//     let mut mod_rs = String::new();
//     for entry in std::fs::read_dir(&generated)? {
//         let path = entry?.path();
//         if path.extension().and_then(|e| e.to_str()) == Some("rs") {
//             if let Some(name) = path.file_stem().and_then(|n| n.to_str()) {
//                 if name != "mod" {
//                     mod_rs += &format!("#[cfg(feature = \"{0}\")]\n", name);
//                     mod_rs += &format!("pub mod {};\n\n", name);
//                 }
//             }
//         }
//     }
//     std::fs::write(generated.join("mod.rs"), mod_rs)?;
//     Ok(())
// }

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
            .client_mod_attribute(stem, format!("#[cfg(feature = \"{}-client\")]", stem))
            .server_mod_attribute(stem, format!("#[cfg(feature = \"{}-server\")]", stem))
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
        mod_rs += &format!(
            "#[cfg(any(feature = \"{0}-client\", feature = \"{0}-server\"))]\n",
            stem
        );
        mod_rs += &format!("pub mod {};\n\n", stem);
    }
    fs::write(out_dir.join("mod.rs"), mod_rs)?;

    Ok(())
}
