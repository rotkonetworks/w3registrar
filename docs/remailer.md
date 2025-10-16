# Remailer Backend Requirements

## WebSocket Server Implementation

### Required Message Types

#### 1. Send Message
**Client → Server**
```json
{
  "type": "remailer_send_message",
  "payload": {
    "recipient_address": "5Gw8r...",
    "content": "Message text with sender info footer",
    "encrypted": false,
    "encrypted_content": "-----BEGIN PGP MESSAGE-----...",
    "contact_type": "email|twitter|matrix|discord",
    "destination": "alice@example.com",
    "network": "polkadot_people",
    "transaction_hash": "0xabc123..."
  }
}
```

**Server → Client**
```json
{
  "payload": {
    "id": "msg_123",
    "sender_address": "5Abc...",
    "recipient_address": "5Gw8r...",
    "content": "Message text",
    "encrypted": false,
    "timestamp": 1697123456789,
    "contact_type": "email",
    "destination": "alice@example.com",
    "status": "sent",
    "network": "polkadot_people"
  }
}
```

#### 2. Fetch Messages
**Client → Server**
```json
{
  "type": "remailer_fetch_messages",
  "payload": {
    "recipient_address": "5Gw8r..."
  }
}
```

**Server → Client**
```json
{
  "payload": [
    {
      "id": "msg_123",
      "sender_address": "5Abc...",
      "content": "...",
      "timestamp": 1697123456789,
      "status": "sent",
      ...
    }
  ]
}
```

#### 3. Delete Message
**Client → Server**
```json
{
  "type": "remailer_delete_message",
  "payload": {
    "message_id": "msg_123"
  }
}
```

**Server → Client**
```json
{
  "payload": {
    "success": true
  }
}
```

#### 4. Message Status Updates (Push)
**Server → Client**
```json
{
  "type": "remailer_message_update",
  "payload": {
    "id": "msg_123",
    "status": "sent|failed|pending",
    ...
  }
}
```

---

## Backend Logic

### 1. Transaction Verification
```rust
async fn verify_payment(tx_hash: &str, network: &str) -> Result<bool> {
    // Connect to chain RPC
    let api = connect_chain(network).await?;

    // Get transaction
    let tx = api.get_transaction(tx_hash).await?;

    // Verify:
    // 1. Transaction is finalized
    // 2. Transaction succeeded (no errors)
    // 3. Amount matches remailer fee
    // 4. Recipient is remailer address
    // 5. Transaction is recent (< 5 minutes old)

    Ok(true)
}
```

### 2. Optional: Sender Verification (Opt-in)
```rust
async fn check_sender_verified(address: &str, network: &str) -> Result<bool> {
    // Query Identity.IdentityOf from chain
    let identity = api.query_identity(address).await?;

    if let Some(identity) = identity {
        // Check judgements for Reasonable or KnownGood
        for judgement in identity.judgements {
            if matches!(judgement.1, Judgement::Reasonable | Judgement::KnownGood) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}
```

### 3. Message Forwarding

#### Email
```rust
async fn send_email(to: &str, content: &str) -> Result<()> {
    // Use SMTP server
    // From: noreply@your-remailer.com
    // To: recipient email from identity
    // Subject: "Message via W3 Remailer"
    // Body: content
}
```

#### Twitter DM
```rust
async fn send_twitter_dm(handle: &str, content: &str) -> Result<()> {
    // Twitter API v2
    // POST /2/dm_conversations/with/:participant_id/messages
    // Requires Twitter API access + user OAuth
}
```

#### Matrix
```rust
async fn send_matrix_message(matrix_id: &str, content: &str) -> Result<()> {
    // Matrix Client-Server API
    // PUT /_matrix/client/v3/rooms/{roomId}/send/m.room.message/{txnId}
    // Requires matrix server + access token
}
```

#### Discord
```rust
async fn send_discord_dm(discord_handle: &str, content: &str) -> Result<()> {
    // Discord API
    // POST /users/@me/channels (create DM channel)
    // POST /channels/{channel.id}/messages
    // Requires Discord bot token
}
```

### 4. Rate Limiting
```rust
// Per address rate limits
const MAX_MESSAGES_PER_HOUR: u32 = 10;
const MAX_MESSAGES_PER_DAY: u32 = 50;

async fn check_rate_limit(sender: &str) -> Result<bool> {
    let redis = get_redis_client();

    let hour_key = format!("ratelimit:{}:hour", sender);
    let day_key = format!("ratelimit:{}:day", sender);

    let hour_count: u32 = redis.get(&hour_key).unwrap_or(0);
    let day_count: u32 = redis.get(&day_key).unwrap_or(0);

    if hour_count >= MAX_MESSAGES_PER_HOUR || day_count >= MAX_MESSAGES_PER_DAY {
        return Ok(false);
    }

    redis.incr(&hour_key).expire(&hour_key, 3600);
    redis.incr(&day_key).expire(&day_key, 86400);

    Ok(true)
}
```

---

## PGP Key Storage (Simple Approach)

Store PGP public keys in backend database, referenced by on-chain fingerprint.

### Database Schema
```sql
CREATE TABLE pgp_keys (
    fingerprint TEXT PRIMARY KEY,
    address TEXT NOT NULL,
    network TEXT NOT NULL,
    armored_key TEXT NOT NULL,
    uploaded_at TIMESTAMP DEFAULT NOW(),
    verified BOOLEAN DEFAULT FALSE,
    UNIQUE(address, network)
);

CREATE INDEX idx_address_network ON pgp_keys(address, network);
```

### Upload Key Endpoint
**Client → Server**
```json
{
  "type": "pgp_upload_key",
  "payload": {
    "address": "5Gw8r...",
    "network": "polkadot_people",
    "armored_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...",
    "fingerprint": "1234567890ABCDEF1234567890ABCDEF12345678"
  }
}
```

**Server validates:**
1. Parse PGP key and extract fingerprint
2. Verify fingerprint matches payload
3. Verify fingerprint matches on-chain identity data
4. Store in database

**Server → Client**
```json
{
  "payload": {
    "success": true,
    "fingerprint": "1234..."
  }
}
```

### Fetch Key Endpoint
**Client → Server**
```json
{
  "type": "pgp_fetch_key",
  "payload": {
    "fingerprint": "1234567890ABCDEF1234567890ABCDEF12345678"
  }
}
```

**Server → Client**
```json
{
  "payload": {
    "armored_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...",
    "verified": true
  }
}
```

---

## Security Considerations

### 1. Input Validation
- Validate all SS58 addresses
- Sanitize message content (remove HTML/scripts)
- Verify contact destinations (valid email, Twitter handle, etc.)
- Limit message length per platform

### 2. Transaction Validation
- **MUST** verify transaction on-chain before forwarding
- Check transaction finality (not just in mempool)
- Verify correct amount and recipient
- Prevent replay attacks (store used tx hashes)

### 3. Privacy
- Don't log message content
- Redact addresses in logs
- Use secure connections (TLS) for all forwarding
- Consider message retention policy (auto-delete after N days)

### 4. Spam Prevention
- Rate limiting (see above)
- Require payment for each message
- Optional: recipient can block senders
- Optional: verification requirement per recipient preference

---

## Database Schema

```sql
CREATE TABLE messages (
    id UUID PRIMARY KEY,
    sender_address TEXT NOT NULL,
    recipient_address TEXT NOT NULL,
    content TEXT NOT NULL,
    encrypted BOOLEAN DEFAULT FALSE,
    contact_type TEXT NOT NULL,
    destination TEXT NOT NULL,
    network TEXT NOT NULL,
    transaction_hash TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT NOW(),
    sent_at TIMESTAMP,
    error TEXT
);

CREATE INDEX idx_recipient ON messages(recipient_address);
CREATE INDEX idx_sender ON messages(sender_address);
CREATE INDEX idx_tx_hash ON messages(transaction_hash);

CREATE TABLE used_transactions (
    tx_hash TEXT PRIMARY KEY,
    used_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE rate_limits (
    address TEXT NOT NULL,
    window_start TIMESTAMP NOT NULL,
    count INTEGER DEFAULT 1,
    PRIMARY KEY (address, window_start)
);
```

---

## Environment Variables

```bash
# WebSocket
WS_HOST=0.0.0.0
WS_PORT=8080
WS_TLS_CERT=/path/to/cert.pem
WS_TLS_KEY=/path/to/key.pem

# Chain RPC endpoints
POLKADOT_RPC=wss://polkadot-people-rpc.polkadot.io
KUSAMA_RPC=wss://kusama-people-rpc.polkadot.io
PASEO_RPC=wss://paseo-rpc.dwellir.com

# Remailer wallet
REMAILER_ADDRESS=5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY
REMAILER_FEE_POLKADOT=100000000  # 0.01 DOT
REMAILER_FEE_KUSAMA=333333333    # 0.1 KSM
REMAILER_FEE_PASEO=100000000     # 0.01 PAS

# Email (SMTP)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=noreply@your-domain.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=W3 Remailer <noreply@your-domain.com>

# Twitter API
TWITTER_API_KEY=...
TWITTER_API_SECRET=...
TWITTER_BEARER_TOKEN=...

# Matrix
MATRIX_HOMESERVER=https://matrix.org
MATRIX_ACCESS_TOKEN=...
MATRIX_USER_ID=@remailer:matrix.org

# Discord
DISCORD_BOT_TOKEN=...
DISCORD_CLIENT_ID=...

# Database
DATABASE_URL=postgresql://user:pass@localhost/remailer

# Redis (rate limiting)
REDIS_URL=redis://localhost:6379

# PGP Keyserver
KEYSERVER_URL=https://keyserver.ubuntu.com
```

---

## Deployment Checklist

- [ ] WebSocket server with WSS (TLS certificate)
- [ ] PostgreSQL database
- [ ] Redis for rate limiting
- [ ] Chain RPC connections (Polkadot, Kusama, Paseo)
- [ ] SMTP server access for email
- [ ] Twitter API credentials (if supporting Twitter)
- [ ] Matrix homeserver + bot account (if supporting Matrix)
- [ ] Discord bot (if supporting Discord)
- [ ] PGP keyserver access (Ubuntu keyserver works)
- [ ] Monitoring/logging (Sentry, DataDog, etc.)
- [ ] Backup strategy for message database

---

## Minimal MVP Implementation Order

1. **WebSocket server** (wss://)
2. **Database** (PostgreSQL)
3. **Transaction verification** (query Polkadot/Kusama chains)
4. **Email forwarding only** (easiest to implement)
5. **Rate limiting** (Redis)
6. **Message storage & retrieval**

Defer for v2:
- Twitter/Matrix/Discord support
- PGP encryption (use Ubuntu keyserver when ready)
- Advanced spam filtering
- Message encryption at rest
- Recipient preferences (verified-only, blocklists)
