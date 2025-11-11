use crate::server::download_token::DownloadToken;
use crate::server::files::FileManager;
use crate::server::security::Security;
use crate::server::state::State;
use crate::server::token_store::TokenStore;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use std::time::SystemTime;

use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::{Duration, sleep};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::oneshot,
};
use tokio_rustls::server::TlsStream;
use tracing::{error, info};
use uuid::Uuid;
use zeroize::Zeroizing;

pub struct Client {
    pub uuid: Uuid,
    socket: TlsStream<TcpStream>,
    address: core::net::Ipv4Addr,
    state: Arc<State>,
    security: Arc<Security>,
    file_manager: Arc<FileManager>,
    token_store: Arc<TokenStore>,
}

impl Client {
    pub fn new(
        uuid: Uuid,
        socket: TlsStream<TcpStream>,
        address: core::net::Ipv4Addr,
        state: Arc<State>,
        security: Arc<Security>,
        file_manager: Arc<FileManager>,
        token_store: Arc<TokenStore>,
    ) -> Self {
        Self {
            uuid,
            socket,
            address,
            state,
            security,
            file_manager,
            token_store,
        }
    }
    pub async fn run(mut self) {
        //Show banner
        let banner1 = r#"
            _
           //\
           V  \
            \  \_
             \,'.`-.
              |\ `. `.
              ( \  `. `-.                        _,.-:\
               \ \   `.  `-._             __..--' ,-';/
                \ `.   `-.   `-..___..---'   _.--' ,'/
                 `. `.    `-._        __..--'    ,' /
                   `. `-_     ``--..''       _.-' ,'
                     `-_ `-.___        __,--'   ,'
                        `-.__  `----"""    __.-'
                             `--..____..--'

      ____                                ________                __
     / __ )____ _____  ____ _____  ____ _/ ____/ /___  __  ______/ /
    / __  / __ `/ __ \/ __ `/ __ \/ __ `/ /   / / __ \/ / / / __  /
   / /_/ / /_/ / / / / /_/ / / / / /_/ / /___/ / /_/ / /_/ / /_/ /
  /_____/\__,_/_/ /_/\__,_/_/ /_/\__,_/\____/_/\____/\__,_/\__,_/


            "#;

        let banner_f1 = banner1.to_string();
        let formatted_banner = format!("{}", banner_f1);
        let _ = self.socket.write_all(formatted_banner.as_bytes()).await;
        let _ = self
            .socket
            .write_all(b"\n [*] Enter password to log in: ")
            .await;
        // Autentication block
        let mut pass_buffer = [0; 512];
        match self.socket.read(&mut pass_buffer).await {
            Ok(0) => {
                // Client sends no data
                info!(
                    "[SERVER] Client disconnected while was on autentication: {}",
                    self.address.to_string()
                );
                // Unregister client from state
                self.state.remove_session(self.uuid).await;
                self.state.decrease_clients_count().await;
                info!(
                    "[SERVER] Client disconnected on: {}",
                    self.address.to_string()
                );
                info!(
                    "[SYSTEM] Total clients connected: {}",
                    self.state.get_clients_count().await
                );
                return;
            }
            Ok(n) => {
                let pass_introduced = Zeroizing::new(
                    String::from_utf8_lossy(&pass_buffer[..n])
                        .trim()
                        .to_string(),
                );
                if Self::verify_password(&pass_introduced, self.state.server_password_hash()) {
                    drop(pass_introduced);
                    // Replace by secure password verification
                    if let Err(e) = self
                        .socket
                        .write_all(b"\n [*] Logged successfully!\n")
                        .await
                    {
                        error!("[ERROR] Cannot send data to client: {}", e);
                    }
                } else {
                    if let Err(e) = self.socket.write_all(b"Access denied.\n").await {
                        error!("[ERROR] Cannot send data to client: {}", e);
                    }
                    error!(
                        "[ERROR] Client [{}] failed on login.",
                        self.address.to_string()
                    );
                    // Register bad login attempt
                    self.security.register_log_att(self.address).await;
                    // Unregister client from state
                    self.state.remove_session(self.uuid).await;
                    self.state.decrease_clients_count().await;
                    return;
                }
            }
            Err(e) => {
                error!("[ERROR] Cannot read data from client: {}", e);
                // Unregister client from state
                self.state.remove_session(self.uuid).await;
                self.state.decrease_clients_count().await;
                info!(
                    "[SERVER] Client disconnected on: {}",
                    self.address.to_string()
                );
                info!(
                    "[SYSTEM] Total clients connected: {}",
                    self.state.get_clients_count().await
                );
            }
        }
        // - - - TIMEOUT IMPLEMENTATION - - - //
        let (tx_reset, mut rx_reset) = watch::channel(()); // Channel to reset the counter
        let (tx_close, mut rx_close) = oneshot::channel::<()>();
        let uuid = self.uuid;
        let state_for_timeout = self.state.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = rx_reset.changed() => {}
                    _ = sleep(Duration::from_secs(120)) => {
                        tracing::warn!("[TIMEOUT] Client [{}] disconnected due inactivity.\n", uuid);
                        state_for_timeout.remove_session(uuid).await;
                        state_for_timeout.decrease_clients_count().await;
                        let _ = tx_close.send(());
                        return;
                    }
                }
            }
        });
        // Show available files
        let available_files = format!("\n{}\n", self.file_manager.list_files_formatted());
        let _ = self.socket.write_all(available_files.as_bytes()).await;
        let _ = self
            .socket
            .write_all(b"  =================================================================\n\n")
            .await;
        let _ = self.socket.write_all(b" [*] > ").await;
        // Main loop which reads data from client
        let mut buffer = [0; 512];
        loop {
            tokio::select! {
                _ = &mut rx_close => {
                    let _ = self.socket.shutdown().await;
                    return;
                }
                res = self.socket.read(&mut buffer) => {
                    match res {
                        Ok(0) => {
                            // Client sends no data
                            info!(
                                "[SERVER] Client disconnected while was on autentication: {}",
                                self.address.to_string()
                            );
                            // Unregister client from state
                            self.state.remove_session(self.uuid).await;
                            self.state.decrease_clients_count().await;
                            info!(
                                "[SERVER] Client disconnected on: {}",
                                self.address.to_string()
                            );
                            info!(
                                "[SYSTEM] Total clients connected: {}",
                                self.state.get_clients_count().await
                            );
                            return;
                        }
                        Ok(n) => {
                            // Restart timeout task
                            let _ = tx_reset.send(());
                            // Receive data from client
                            let data = String::from_utf8_lossy(&buffer[..n]).trim().to_string();
                            if !self.parse_command(&data).await {
                                info!("[CLIENT {}] Session ended by command.", self.uuid);
                                let _ = self.socket.shutdown().await;
                                return;
                            }
                        }
                        Err(e) => {
                            error!("[ERROR] Cannot read data from client: {}", e);
                            // Unregister client from state
                            self.state.remove_session(self.uuid).await;
                            self.state.decrease_clients_count().await;
                            info!(
                                "[SERVER] Client disconnected on: {}",
                                self.address.to_string()
                            );
                            info!(
                                "[SYSTEM] Total clients connected: {}",
                                self.state.get_clients_count().await
                            );
                            return;
                        }
                    }
                }
            }
        }
    }
    pub async fn parse_command(&mut self, input: &str) -> bool {
        let mut parts = input.split_whitespace();
        let cmd_name = parts.next().unwrap_or("");
        match cmd_name {
            "DOWNLOAD" => {
                if let Some(filename_arg) = parts.next() {
                    if !self.file_manager.file_exists(filename_arg) {
                        if let Err(e) = self.socket.write_all(b" [SERVER] File not found").await {
                            error!("[ERROR] Cannot send data to client: {}\n", e);
                        }
                        return true;
                    }
                    let uuid = Uuid::new_v4();
                    let expiration = SystemTime::now() + Duration::from_secs(300);
                    let token =
                        DownloadToken::new(uuid, filename_arg.to_string(), expiration, false);
                    self.token_store.insert(token.clone()).await;
                    // Generate URL
                    let url = format!(
                        "https://{}:{}/download/{}",
                        self.state.server_host.to_string(),
                        self.state.http_server_port,
                        uuid
                    );
                    let msg = format!(" [TOKEN] {}\n", url);
                    if let Err(e) = self.socket.write_all(msg.as_bytes()).await {
                        error!("[ERROR] Cannot send data to client: {}\n", e);
                    }
                } else {
                    let _ = self
                        .socket
                        .write_all(b" [ERROR] 'DOWNLOAD' command needs an argument.\n")
                        .await;
                }
                let _ = self.socket.write_all(b" [*] > ").await;
            }
            _ => {
                println!("Unknown command");
                let _ = self.socket.write_all(b" [*] > ").await;
            }
        }
        true
    }
    fn verify_password(input_password: &str, stored_hash: &str) -> bool {
        let clean_pw = input_password.trim_matches(|c| c == '\r' || c == '\n' || c == ' ');
        if let Ok(parsed_hash) = PasswordHash::new(stored_hash) {
            Argon2::default()
                .verify_password(clean_pw.as_bytes(), &parsed_hash)
                .is_ok()
        } else {
            false
        }
    }
}
