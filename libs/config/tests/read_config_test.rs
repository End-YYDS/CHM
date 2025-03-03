use config::*;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use tempfile::tempdir;
#[test]
fn test_load_config_from_current_dir() {
    let dir = tempdir().expect("Unable to create a temporary directory");
    let config_path: PathBuf = dir.path().join("config.json");
    let json_config = r#"{
    "TRUSTED_DOMAINS": [
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://localhost:5173"
    ],
    "ALLOWED_ORIGINS": [
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://localhost:5173"
    ],
    "ALLOWED_METHODS": [
        "GET",
        "POST",
        "PUT"
    ],
    "ALLOWED_HEADERS": [
        "Authorization",
        "Content-Type",
        "X-Custom-Header"
    ],
    "CORS_MAX_AGE": 3600,
    "CHM_GRPC_SERVICE_IP": "127.0.0.1:50051",
    "CHM_REST_SERVICE_IP": "127.0.0.1:8080",
    "DEBUG": true
}"#;
    {
        let mut file = File::create(&config_path).expect("Unable to create a file");
        file.write_all(json_config.as_bytes())
            .expect("Unable to write to the file");
    }
    let original_dir = env::current_dir().expect("Unable to get the current directory");
    env::set_current_dir(&dir).expect("Unable to set the current directory");
    let cmg = get_config_manager(None);
    assert_eq!(cmg.get_trusted_domains().len(), 3);
    assert_eq!(cmg.get_allowed_origins().len(), 3);
    assert_eq!(cmg.get_allowed_methods().len(), 3);
    assert_eq!(cmg.get_allowed_headers().len(), 3);
    assert_eq!(cmg.get_cors_max_age(), 3600);
    env::set_current_dir(original_dir).expect("failed to restore original directory");
}
