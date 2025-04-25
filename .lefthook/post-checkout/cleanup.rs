use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args[3] == "1" {
        println!("Cleaning up after checkout...");
        let current_dir = env::current_dir().unwrap();
        let targetDir = Path::new(&current_dir).join("target");
        if targetDir.exists() {
            println!("Removing target directory...");
            fs::remove_dir_all(&targetDir).expect("Failed to remove target directory");
        } else {
            println!("Target directory does not exist, nothing to clean up.");
        }
        let node_modules_dir = Path::new(&current_dir)
            .join("frontend")
            .join("node_modules");
        if node_modules_dir.exists() {
            println!("Removing node_modules directory...");
            fs::remove_dir_all(&node_modules_dir).expect("Failed to remove node_modules directory");
        } else {
            println!("node_modules directory does not exist, nothing to clean up.");
        }
    } else {
        println!("No cleanup needed.");
    }
}
