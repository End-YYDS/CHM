use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let generated = Path::new("src/generated");
    if !generated.exists() {
        std::fs::create_dir_all(generated)?;
    }
    tonic_build::configure()
        .out_dir("src/generated")
        .compile_protos(&["dns.proto"], &["proto"])
        .unwrap_or_else(|e| panic!("Failed to compile protos {:?}", e));
    Ok(())
}
