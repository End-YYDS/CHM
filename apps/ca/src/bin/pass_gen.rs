type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
use std::io;

use password::*;
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--encode") {
        let mut password = String::new();
        println!("Enter Password: ");
        io::stdin().read_line(&mut password)?;
        let hash_pass = hash_password(password.trim())?;
        println!("Encoded Password: {hash_pass}");
        return Ok(());
    }
    if args.iter().any(|a| a == "--base64-decode") {
        let mut hash_pass = String::new();
        println!("Enter Base64 Encoded Password: ");
        io::stdin().read_line(&mut hash_pass)?;
        let decoded_base64 = decode_base64(hash_pass.trim())?;
        println!("Decoded Base64: {decoded_base64}");
        return Ok(());
    }
    if args.iter().any(|a| a == "--base64-encode") {
        let mut hash_pass = String::new();
        println!("Enter Base64 Encoded Password: ");
        io::stdin().read_line(&mut hash_pass)?;
        let encoded_base64 = encode_base64(hash_pass.trim());
        println!("Encoded Base64: {encoded_base64}");
        return Ok(());
    }
    Ok(())
}
