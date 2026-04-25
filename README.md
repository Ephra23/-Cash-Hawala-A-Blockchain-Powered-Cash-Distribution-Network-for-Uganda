# Cash Hawala Uganda — MVP

> *"Code enforces trust, humans handle cash."*

A blockchain-powered cash distribution protocol converting USDC → physical UGX
without banks, mobile money, or P2P platforms.

---

## Architecture

```
Sender PWA / SMS
      │
      ▼
Cloudflare Worker  ←→  KV (ephemeral: PINs 24h, metadata 7d)
      │                     Africa's Talking SMS API
      │                     Telegram Bot API
      ▼
Polygon PoS (chainId 137)
      ├── CashHawalaEscrow.sol   (escrow + dispute logic)
      └── ReputationRegistry.sol (agent reputation + vouching)
      │
      ▼
Local Agent (cash handoff)
      │
      ▼
Receiver (physical UGX)
```

---

## File Structure

```
├── contracts/
│   ├── CashHawalaEscrow.sol       — Core escrow logic
│   └── ReputationRegistry.sol     — Agent reputation + vouching
├── worker/
│   └── src/index.ts               — Cloudflare Worker (serverless backend)
└── pwa/
    └── index.html                 — Single-file PWA (React-free, <200KB)
```

---

## Smart Contract Deployment (Polygon PoS)

### Prerequisites
- Foundry or Hardhat
- MATIC for gas (~$0.01 per deployment)
- USDC on Polygon: `0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174`

### With Foundry

```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash && foundryup

# Clone repo and navigate to contracts/
cd contracts/

# Deploy CashHawalaEscrow
forge create CashHawalaEscrow \
  --rpc-url https://polygon-rpc.com \
  --private-key $DEPLOYER_KEY \
  --constructor-args $FEE_RECIPIENT_ADDRESS \
  --verify \
  --etherscan-api-key $POLYGONSCAN_KEY

# Note the deployed address, then deploy ReputationRegistry
forge create ReputationRegistry \
  --rpc-url https://polygon-rpc.com \
  --private-key $DEPLOYER_KEY \
  --constructor-args $ESCROW_ADDRESS $ORACLE_ADDRESS

# Approve USDC on escrow
cast send $ESCROW_ADDRESS \
  "approveToken(address,bool)" \
  0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174 true \
  --rpc-url https://polygon-rpc.com \
  --private-key $DEPLOYER_KEY
```

### Post-Deploy Configuration

```bash
# Add initial arbiters (3+ required for disputes)
cast send $ESCROW_ADDRESS "addArbiter(address)" $ARBITER_1 ...
cast send $ESCROW_ADDRESS "addArbiter(address)" $ARBITER_2 ...
cast send $ESCROW_ADDRESS "addArbiter(address)" $ARBITER_3 ...
```

---

## Cloudflare Worker Deployment

### Prerequisites
- Cloudflare account (free tier sufficient for MVP)
- `wrangler` CLI

```bash
# Install wrangler
npm install -g wrangler
wrangler login

# Create KV namespace
wrangler kv:namespace create "HAWALA_KV"
# Note the namespace ID

# Set secrets
wrangler secret put AT_API_KEY        # Africa's Talking API key
wrangler secret put AT_USERNAME       # Africa's Talking username
wrangler secret put TELEGRAM_BOT_TOKEN
wrangler secret put ORACLE_PRIVATE_KEY  # EOA key for reputation signing
wrangler secret put POLYGON_RPC       # e.g. https://polygon-rpc.com
wrangler secret put ESCROW_ADDRESS    # deployed escrow address
wrangler secret put ALLOWED_ORIGIN    # your PWA domain
```

### wrangler.toml

```toml
name = "cash-hawala"
main = "src/index.ts"
compatibility_date = "2024-01-01"

[[kv_namespaces]]
binding = "KV"
id = "YOUR_KV_NAMESPACE_ID"

[vars]
ENVIRONMENT = "production"
```

```bash
# Deploy
wrangler deploy

# Set Telegram webhook
curl "https://api.telegram.org/bot$BOT_TOKEN/setWebhook" \
  -d "url=https://cash-hawala.workers.dev/webhook/telegram"
```

---

## PWA Deployment

The `pwa/index.html` is a self-contained single file. Deploy anywhere:

```bash
# Cloudflare Pages (recommended — free, global CDN)
wrangler pages deploy pwa/ --project-name cash-hawala-pwa

# Or any static host:
# Netlify, Vercel, GitHub Pages, etc.
```

Update `CONFIG.API_BASE` in `pwa/index.html` to your Worker URL before deploying.

---

## Agent Onboarding

1. Agent visits PWA → Agent tab → Register
2. Core team manually vets application (Google Form + video call)
3. Agent deposits $50 USDC collateral on-chain:
   ```
   registerAgent(USDC_ADDRESS, 50000000, 200000)  // UGX 200k provisional limit
   ```
4. Admin activates: `agents[wallet].active = true` (via owner call)
5. Agent adds Telegram bot: `t.me/CashHawalaBot`
6. After 10 deliveries, admin calls `verifyAgent(agentAddr)` → limits increase

---

## Security Checklist

- [x] Re-entrancy: state updated before external calls in `confirmDelivery`
- [x] Access control: `onlyAgent` modifier + arbiter assignment checks
- [x] PIN not stored on-chain: only keccak commitment stored
- [x] Receiver PII not stored: only keccak256(phone+salt)
- [x] Single-use PINs: KV key deleted immediately on verification
- [x] Collateral slashing: 10% on dispute loss, deactivation below minimum
- [x] Transfer cap: $500 USDC per transfer (regulatory compliance)
- [x] Dispute window: 24h after expiry, prevents premature refunds
- [ ] TODO: Chainlink VRF for arbiter selection (replace pseudo-random)
- [ ] TODO: Multi-sig for admin functions
- [ ] TODO: Formal audit before mainnet scale

---

## Regulatory Awareness (Uganda Protection of Sovereignty Bill 2026)

The protocol is designed to operate within constraints:

- **No Ugandan entity holds funds**: escrow is self-executing code on Polygon
- **Per-transfer cap**: $500 USD (configurable, stays under reporting thresholds)
- **No KYC on-chain**: receiver identity is a one-way hash; protocol is pseudonymous
- **No mobile money**: entirely separate rail — blockchain + physical cash
- **Foreign payment caps**: enforced by `MAX_TRANSFER_USDC` constant in escrow
- **Ministerial approval**: not required as funds never enter Ugandan banking system

*Consult legal counsel before operating at scale. This is a technical MVP.*

---

## SMS USSD Flow (No Smartphone Required)

Receivers without smartphones can participate via SMS:

```
Receiver SMS flow:
  Sender → shares PIN verbally or via SMS → Receiver
  Receiver → goes to agent location → shows PIN verbally
  Agent → enters PIN in their app → releases cash
  Agent → sends confirmation SMS → receiver replies YES
```

Africa's Talking USSD shortcode (optional):
```
*483*HAWALA# → Check PIN status
*483*HAWALA*PINCODE# → Verify collection
```

---

## Estimated Costs (per transfer)

| Component | Cost |
|---|---|
| Polygon gas (initiateTransfer) | ~$0.002 |
| Polygon gas (confirmDelivery) | ~$0.001 |
| Africa's Talking SMS (Uganda) | ~$0.01 per SMS |
| Cloudflare Worker (free tier: 100k req/day) | $0 |
| Protocol fee to agent | 1.5% of transfer |

---

## Contact & Telegram Bot Setup

1. Message `@BotFather` on Telegram
2. Create bot: `/newbot` → name: "Cash Hawala Uganda" → username: `CashHawalaUGBot`
3. Copy token → set as `TELEGRAM_BOT_TOKEN` secret
4. Set webhook URL to your Worker endpoint
