# Identity Registrar

## w3registrar

Lightweight Substrate registrar microservice that automates identity verification.
It listens for `JudgementRequested` events, manages verification tokens in Redis,
and issues final on-chain judgements once all fields (email, Matrix, Discord, etc.)
are confirmed.

---

### Quickstart (Download Latest Binary)

1. **Fetch & make executable**:
   ```bash
   curl -s https://api.github.com/repos/rotkonetworks/w3registrar/releases/latest \
     | jq -r '.assets[] | select(.name == "w3registrar-linux-amd64") | .browser_download_url' \
     | xargs curl -LO

   chmod +x w3registrar-linux-amd64
   ```
2. **Provide config** (`config.toml` in the same directory, or set `CONFIG_PATH=/path/to/config.toml`).
3. **Run**:
   ```bash
   ./w3registrar-linux-amd64
   ```

---

### Building from Source

```bash
git clone https://github.com/rotkonetworks/w3registrar.git
cd w3registrar

# To get the metadata files, you can get them using following commands:
git lfs install
git lfs pull 
# If you fun into an error such as "git: 'lfs' is not a git command. See 'git --help'."
#   please refer to https://stackoverflow.com/a/48734334 in odert to get it installed and try again.

# Nix-based build environment (recommended):
nix-shell
cargo build --release

# Or without Nix, just ensure Rust nightly + dependencies are installed:
cargo build --release

./target/release/w3registrar
```

---

### Configuration

An example `config.toml`:

```toml
[registrar.rococo]
endpoint = "wss://dev.rotko.net/people-rococo/"
registrar_index = 0
keystore_path = "./keyfile.rococo"
identity_proxied = false
fields = ["email","matrix","twitter","discord","display_name"]

[registrar.paseo]
endpoint = "wss://people-paseo.dotters.network"
registrar_index = 1
keystore_path = "./keyfile.paseo"
identity_proxied = true
fields = ["email","matrix","twitter","discord","display_name"]

[websocket]
host = "127.0.0.1"
port = 8080

[redis]
host = "127.0.0.1"
port = 6379

[adapter.matrix]
homeserver = "https://matrix.org"
username = "regbot"
password = "abc123"
security_key = "EfT0 1WXL nIi8 v1Zx 15c8 B8Ux bKdS fLUZ 5uVk zje7 KYFj ZiLf"
admins = ["@sara:matrix.org","@bill:matrix.org"]
state_dir = "/tmp/matrix_"

[adapter.email]
email = "w3reg@rotko.net"
username = "w3reg"
password = "pw"
name = "w3registrar"
mailbox = "INBOX"
server = "mail.rotko.net"
port = 143
```

> **Tip**: You can customize each `[registrar.<network>]` section for the Substrate endpoint, registrar index, identity fields, etc.  

---

### Behavior

- **Substrate**:
  - Connects to the listed endpoints, listens for `JudgementRequested`, checks identity fields, and writes partial verification state to Redis.
  - If the user unrequests judgement, the state is removed.
- **Redis**:
  - Persists in-flight challenges. Example key: `"<accountId>:<network>"`.
  - Publishes keyspace events used by the WebSocket server to notify clients when states change.
- **WebSocket**:
  - Runs on `host:port` from `[websocket]` section.
  - Accepts JSON messages of type `SubscribeAccountState` (to watch an account’s fields) or `VerifyIdentity` (to mark a challenge done).
  - On changes, pushes updated state back to any subscribed clients.
- **Email**:
  - If any `fields` contains `"email"`, w3registrar spawns one IMAP loop that watches a single mailbox.  
  - Unread emails are parsed; if a message body matches the token in Redis, we mark `email` done.
- **Matrix**:
  - If any `fields` is among `"matrix","discord","twitter"`, a single Matrix client logs in, listens for messages.  
  - If a user posts a token that matches the Redis challenge, we mark that done.

Once all fields for a network are done, w3registrar calls `provide_judgement` with `Judgement::Reasonable`.

---

### Example WebSocket Usage

**Subscribe** to an account:
```jsonc
{
  "version": "1.0",
  "type": "SubscribeAccountState",
  "payload": {
    "network": "rococo",
    "account": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
  }
}
```

**Mark Identity Verified** for a challenge token:
```jsonc
{
  "version": "1.0",
  "type": "VerifyIdentity",
  "payload": {
    "network": "rococo",
    "account": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
    "field": "Discord",
    "challenge": "8ABR4K13"
  }
}
```

You can test with [`websocat`](https://github.com/vi/websocat) or a custom client.

---

### Companion Frontend: w3registrar-www

- See [**w3registrar-www**](https://github.com/rotkonetworks/w3registrar-www) for a React/Vue-based frontend (example).
- Connects to the same WebSocket to let users see which fields remain unverified, send tokens, etc.

---

### License

Dual-licensed under MIT or Apache 2.0. See `LICENSE` for details.
