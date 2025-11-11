# 🍌 BananaCloud:

Banana Cloud is a highly secure, private file server implemented in Rust, engineered to provide encrypted storage and fine-grained access control for a trusted set of clients. The system integrates a TCP server with TLS authentication and a HTTPS file server, delivering a reliable and seamless environment for secure file sharing. Its architecture emphasizes robust security, strict client management, and efficient concurrency.

# 🔐 Main Features:

**1. Secure Networking**
  * **TCP Server with TLS:** Handles encrypted client connections over TCP, ensuring confidentiality and integrity of all data in transit. Supports only IPv4 connections for controlled deployment.
  * **HTTPS File Server:** Serves files securely over HTTPS using Rustls and Hyper. Each file download is protected by a unique, expiring token, ensuring only authorized clients can access the data.
  * **Mutual TLS:** Supports client certificate verification (mTLS) for an additional layer of security in trusted environments.
    
**2. Client Authentication & Access Control**
  * **Password-Based Authentication:** Server passwords are hashed with Argon2 and stored securely in memory using Zeroizing to prevent accidental leaks.
  * **Login Attempt Monitoring & IP Banning:** Automatically tracks failed login attempts per client IP. After three failed attempts, the IP is banned to prevent brute-force attacks.
  * **Session Management:** Each client is assigned a UUID, and the server maintains an active session list with concurrent-safe updates.
  * **Inactivity Timeout:** Clients are automatically disconnected after 2 minutes of inactivity, preserving resources and security.

**3. File Management & Safety**
  * **Sanitized File Access:** Prevents path traversal or unauthorized file access. Only files within the designated ./files directory are accessible.
  * **Formatted File Listing:** Provides a clear, organized listing of available files for clients, enhancing usability.
  * **Secure File Reading:** Efficiently reads files into memory while handling errors gracefully and logging all access events.

**4. Download Token System**
  * **Single-Use, Expiring Tokens:** Each file download generates a unique token that expires after 5 minutes. Tokens are consumed on first use to prevent unauthorized re-downloads.
  * **Token Cleanup:** Periodic cleanup of expired or consumed tokens ensures memory efficiency and prevents stale access.
  * **Secure Download URLs:** Tokens are embedded in HTTPS URLs, providing a safe and convenient download method without exposing direct file paths.

**5. Concurrency & Performance**
  * **Async Architecture with Tokio:** Handles multiple clients concurrently without blocking, ensuring smooth operation under simultaneous connections.
  * **Connection Limit Enforcement:** Limits the number of concurrent TCP clients to 10, maintaining stability for private or family use.
  * **Separate Tasks for Clients:** Each client connection runs on a separate asynchronous task, isolating sessions and reducing the risk of global failures.

**6. Logging & Monitoring**
  * **Structured Logging with Tracing:** Tracks authentication attempts, client connections/disconnections, token generation/consumption, and security events.
  * **Detailed Session Information:** Provides administrators with real-time visibility into active sessions and connected clients.

**7. Modular & Extensible Design**
  * **Clean Architecture:** Separates networking, authentication, file management, token handling, and security into dedicated modules.
  * **Easy to Extend:** New commands, additional authentication methods, or file operations can be integrated with minimal impact on existing code.

# ⚙️ PREVIOUS REQUIREMENTS:
* Rust's cargo package manager for compiling Rust.
* Openssl for certificates/keys generation.

# 🚀 SETTING UP GUIDE:
1. Clone the Github repository on your PC: `git clone https://github.com/AdrianUrc/BananaCloud.git`
2. Create the 'available files' directory on project's home-path (Where 'src', 'Cargo.toml', ...) and add your files (for now server can't handle files with spaces on their names): `mkdir files`
3. Exit project's directory and create a new folder to generate the SSL Certificates: `../ && mkdir certs`
4. Move on certs folder and generate SSL CA, certs and keys:
   1. CA private key: `openssl genrsa -out ca-key.pem 4096`
   2. CA cert (valid for 10 years): `openssl req -x509 -new -nodes -key ca-key.pem -sha256 -days 3650 -out ca.pem`
   3. Server private key: `openssl genrsa -out server-key.pem 4096`
   4. Server CSR: `openssl req -new -key server-key.pem -out server.csr`
   5. Sign server's CSR with your CA: `openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -days 365 -sha256`
   6. Client's private key: `openssl genrsa -out client-key.pem 4096`
   7. Client's CSR: `openssl req -new -key client-key.pem -out client.csr`
   8. Sign client's CSR with your CA: `openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out client-cert.pem -days 365 -sha256`
   9. Verify certs: `openssl verify -CAfile ca.pem server-cert.pem` `openssl verify -CAfile ca.pem client-cert.pem`
5. Move 'ca.pem', 'server-cert.pem' and 'server-key.pem' to the project's home-path and rename cert and key as 'cert.pem' and 'key.pem'.
6. Compile the project with 'cargo': `cargo check`
7. Run the project: `cargo run`
8. [OPTIONAL] Generate project's binary: `cargo check --release`

# 🌐 HOW TO CONNECT:
1. Move to the 'certs' folder and make sure 'client-cert', 'client-key' and 'ca.pem' exists.
2. Connect to your own cloud using OpenSSL Client: `openssl s_client -connect <HOST:TCP_PORT> -CAfile ca.pem -cert client-cert.pem -key client-key.pem -quiet`

# 🧭 DEPLOYMENT:
The server can be deployed in various environments depending on your needs:
* **Localhost:** for testing and development on your own machine.
* **Private Network:** by specifying your private IPv4 address during setup, allowing secure access from trusted devices within your LAN.
* **Public Internet:** with proper port-forwarding and a public IPv4 address or DNS record, enabling remote access while maintaining full TLS security.

# 📂 USING AFTER BEING LOGGED:
1. After successfully logging in, review the list of available files displayed in the server banner. Each file listed can be securely downloaded through the integrated HTTPS server.
2. To request a download, enter the following command: `DOWNLOAD <filename.extension>`
3. The server will generate a unique HTTPS download URL containing a temporary access token.
   - The token is valid for 5 minutes and can only be used once.
   - Accessing the URL will start a secure, TLS-encrypted file download through the server’s HTTPS endpoint.
4. Once the token expires or is consumed, a new one must be generated by issuing another `DOWNLOAD` command.








