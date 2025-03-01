use config::*;

#[test]
fn create_config() {
    let _ = get_config_manager(true);
    let path = expand_tilde("~/CHM/config/config.json");
    assert!(path.exists());
}
