use crate::server::{
    files::FileManager, http_server::HttpServer, listener::Listener, security::Security,
    state::State, token_store::TokenStore,
};
use std::sync::Arc;
mod server;
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use rand::rngs::OsRng;
use regex::Regex;
use std::io::{self, Write};
use std::net::IpAddr;
use zeroize::{Zeroize, Zeroizing};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .with_thread_names(true)
        .init();
    // Banner
    let banner = r#"

      ____  ___    _   _____    _   _____       ________    ____  __  ______     __    ____  ___________
     / __ )/   |  / | / /   |  / | / /   |     / ____/ /   / __ \/ / / / __ \   / /   / __ \/ ____/ ___/
    / __  / /| | /  |/ / /| | /  |/ / /| |    / /   / /   / / / / / / / / / /  / /   / / / / / __ \__ \
   / /_/ / ___ |/ /|  / ___ |/ /|  / ___ |   / /___/ /___/ /_/ / /_/ / /_/ /  / /___/ /_/ / /_/ /___/ /
  /_____/_/  |_/_/ |_/_/  |_/_/ |_/_/  |_|   \____/_____/\____/\____/_____/  /_____/\____/\____//____/

        "#;
    println!("{}\n", banner.to_string());
    println!("- - - - - - - - - - - - - Cloud Setup - - - - - - - - - - - - -\n");
    // Ask for ports before initializing
    let host = read_host(" [*] Enter server IP/DNS (or 'localhost'): ");
    let host_clone = host.clone();
    let tcp_server_port = read_port(" [*] Enter TCP server PORT: ");
    let http_server_port = read_port(" [*] Enter HTTPS server PORT: ");
    let http_server_p_clone = http_server_port.clone();
    // Ask for server password before initializing
    let mut server_pass = rpassword::prompt_password(" [*] Enter server password: ").unwrap();
    println!("\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");
    let server_hash = Zeroizing::new(hash_password(&server_pass));
    server_pass.zeroize(); // Delete password from memory inmediately after being used
    let security = Arc::new(Security::new());
    let state = Arc::new(State::new(server_hash, host, http_server_port));
    let file_manager = Arc::new(FileManager::new("./files"));
    let token_store = Arc::new(TokenStore::new());
    let tcp_socket_address;
    let http_socket_address;
    if host_clone == "localhost" {
        tcp_socket_address = format!("127.0.0.1:{}", tcp_server_port);
        http_socket_address = format!("127.0.0.1:{}", http_server_p_clone);
    } else {
        tcp_socket_address = format!("0.0.0.0:{}", tcp_server_port);
        http_socket_address = format!("0.0.0.0:{}", http_server_port);
    }
    // Cleanup task for download tokens
    {
        let token_store_clone = token_store.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                token_store_clone.cleanup().await;
            }
        });
    }
    tracing::info!("[*] Server password hashed and stored securely in memory.");
    let security_clone = security.clone();
    let tcp_listener = Listener::new(
        tcp_socket_address.to_string(),
        state,
        security_clone,
        file_manager.clone(),
        token_store.clone(),
    );
    let http_server = HttpServer::new(
        http_socket_address.to_string(),
        file_manager.clone(),
        token_store.clone(),
    );
    tracing::info!("[*] Starting Banana Cloud on IP/DNS {}...", host_clone);
    tracing::info!("[*] Starting TCP server on port {}...", tcp_server_port);
    tracing::info!(
        "[*] Starting HTTPS file server on port {}...",
        http_server_p_clone
    );
    tokio::join!(async { tcp_listener.run().await }, async {
        http_server.run().await
    });
}
fn hash_password(pw: &str) -> String {
    // Generate random and safe salt
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    // Generate Argon2 hash
    argon2
        .hash_password(pw.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string()
}
fn read_port(prompt: &str) -> u16 {
    loop {
        print!("{}", prompt);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_ok() {
            if let Ok(port) = input.trim().parse::<u16>() {
                if port > 0 {
                    return port;
                }
            }
        }
        println!(" [!] Invalid port. Please enter a number between 1 and 65535.");
    }
}
fn read_host(prompt: &str) -> String {
    let dns_regex = Regex::new(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$").unwrap();

    loop {
        print!("{}", prompt);
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            let trimmed = input.trim();

            // localhost
            if trimmed.eq_ignore_ascii_case("localhost") {
                return "127.0.0.1".to_string();
            }

            // verify IP
            if trimmed.parse::<IpAddr>().is_ok() {
                return trimmed.to_string();
            }

            // verify dns
            if dns_regex.is_match(trimmed) {
                return trimmed.to_string();
            }

            println!(
                " [!] Invalid address. Enter a valid IP, 'localhost', or DNS (example: example.duckdns.org)."
            );
        }
    }
}
