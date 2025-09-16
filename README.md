# Identity Registrar

## w3registrar

Lightweight Substrate registrar microservice that automates identity verification.
It listens for `JudgementRequested` events, manages verification tokens in Redis,
indexes identity data in PostgreSQL, and issues final on-chain judgements once all fields 
(email, Matrix, Discord, GitHub, PGP, etc.) are confirmed.

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

# Set up development environment
cargo install subxt-cli
./scripts/metadata.sh

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
registrar_account = "5CiPPseXPECbkjWCa6MnjNokrgYjMqmKndv2rSnekmSK2DjL"
fields = ["email","matrix","twitter","discord","display_name"]

[registrar.paseo]
endpoint = "wss://people-paseo.dotters.network"
registrar_index = 1
keystore_path = "./keyfile.paseo"
registrar_account = "12BtBrcorHAvSeTLYo6YTq8kdiRG948vkvmxHEmSzZjwZ97u"
fields = ["email","matrix","twitter","discord","display_name","pgp_fingerprint","github"]

[http]
host = "0.0.0.0"
port = 3000

[websocket]
host = "0.0.0.0"
port = 8080

[redis]
host = "0.0.0.0"
port = 6379
listener_timeout = 3500
max_open_clients = 100

[postgres]
host = "0.0.0.0"
port = 5432
user = "username"
dbname = "w3registrar"
cert_path = "/path/to/cert.pem"

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
checking_frequency = 500

[adapter.github]
client_id = "your_github_client_id"
client_secret = "your_github_client_secret"
gh_url = "https://github.com/login/oauth/authorize"
redirect_url = "http://your-domain.com/oauth/callback/github"
```

> **Tip**: You can customize each `[registrar.<network>]` section for the Substrate endpoint, registrar index, identity fields, etc.  

---

### Behavior

- **Substrate**:
  - Connects to the listed endpoints, listens for `JudgementRequested`, checks identity fields, and writes partial verification state to Redis.
  - If the user unrequests judgement, the state is removed.
- **PostgreSQL**:
  - Stores identity registration data and indexer state for efficient querying and historical tracking.
  - The indexer component syncs on-chain identity data to the database.
- **Redis**:
  - Persists in-flight challenges. Example key: `"<accountId>:<network>"`.
  - Publishes keyspace events used by the WebSocket server to notify clients when states change.
- **HTTP Server**:
  - Handles GitHub OAuth callbacks for GitHub identity verification.
  - Runs on `host:port` from `[http]` section.
- **WebSocket**:
  - Runs on `host:port` from `[websocket]` section.
  - Accepts JSON messages of type `SubscribeAccountState` (to watch an account's fields), `VerifyPGPKey` (to verify a PGP key), `SearchRegistration` (to search for registration)
  - On changes, pushes updated state back to any subscribed clients.
- **Email**:
  - If any `fields` contains `"email"`, w3registrar spawns one IMAP loop that watches a single mailbox.  
  - Unread emails are parsed; if a message body matches the token in Redis, we mark `email` done.
- **Matrix**:
  - If any `fields` is among `"matrix","discord","twitter"`, a single Matrix client logs in, listens for messages.  
  - If a user posts a token that matches the Redis challenge, we mark that done.
- **GitHub**:
  - OAuth-based verification for GitHub accounts when `"github"` field is included.
  - Users authenticate via GitHub OAuth flow to verify ownership.

Once all fields for a network are done, w3registrar calls `provide_judgement` with `Judgement::Reasonable`.

---

### Example WebSocket Usage

**Subscribe** to an account:
```jsonc
{
  "version": "1.1",
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
  "version": "1.1",
  "type": "VerifyIdentity",
  "payload": {
    "network": "rococo",
    "account": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
    "field": "Discord",
    "challenge": "8ABR4K13"
  }
}
```

**Search** for an indexed registration:
```jsonc
{
  "version": "1.1",
  "type": "SearchRegistration",
  "payload": {
    "outputs": ["WalletID", "Timeline", "Discord", "Github", "Web", "Email", "Network", "Display"], // can be left empty
    "filters": {
        "fields": [ // can be left empty
            { "field": { "Discord": "username" }, "strict": false},
            { "field": { "AccountId32": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"}, "strict": true}
        ],
        "result_size": 3, // optional
    }
  }
}
```
>> Possible output fields ["WalletID", "Discord", "Display", "Email", "Matrix", "Twitter", "Github", "Legal", "Web", "PGPFingerprint", "Timeline", "Network"]  
>> Possible filter fields ["AccountId32", "Twitter", "Discord", "Matrix", "Display", "Legal", "Web", "Email", "Github", "PGPFingerprint"]  

You can test with [`websocat`](https://github.com/vi/websocat) or a custom client.

---

### Returned Objets
#### SearchRegistration
TODO
#### SubscribeAccountState
TODO
#### VerifyPGPKey
TODO

### Companion Frontend: w3registrar-www

- See [**w3registrar-www**](https://github.com/rotkonetworks/w3registrar-www) for a React/Vue-based frontend (example).
- Connects to the same WebSocket to let users see which fields remain unverified, send tokens, etc.

---

### License

Dual-licensed under MIT or Apache 2.0. See `LICENSE` for details.
