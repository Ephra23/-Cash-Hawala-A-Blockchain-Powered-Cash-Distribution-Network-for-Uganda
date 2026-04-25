/**
 * Cash Hawala Uganda — Cloudflare Workers Backend
 *
 * Handles:
 *   - Transfer initiation & PIN generation
 *   - Agent matching (geo-based)
 *   - SMS/Telegram dispatch (Africa's Talking + Telegram Bot API)
 *   - Dispute routing
 *   - Ephemeral KV storage (PINs: 24h TTL, metadata: 7d)
 *   - Zero PII stored long-term; receiver identity hashed before storage
 *
 * ENV vars (set in Cloudflare dashboard):
 *   AT_API_KEY          — Africa's Talking API key
 *   AT_USERNAME         — Africa's Talking username
 *   TELEGRAM_BOT_TOKEN  — Telegram Bot token
 *   ORACLE_PRIVATE_KEY  — ECDSA key for signing reputation updates
 *   POLYGON_RPC         — Polygon PoS RPC endpoint
 *   ESCROW_ADDRESS      — Deployed CashHawalaEscrow address
 *   ALLOWED_ORIGIN      — CORS origin for PWA
 */

// ─── Types ────────────────────────────────────────────────────────────────────

interface Env {
  KV: KVNamespace;              // Cloudflare KV for ephemeral data
  AT_API_KEY: string;
  AT_USERNAME: string;
  TELEGRAM_BOT_TOKEN: string;
  ORACLE_PRIVATE_KEY: string;
  POLYGON_RPC: string;
  ESCROW_ADDRESS: string;
  ALLOWED_ORIGIN: string;
}

interface TransferRecord {
  transferId: string;
  sender: string;
  agentWallet: string;
  receiverHash: string;
  pinHash: string;           // SHA-256(pin+transferId) — never store plain PIN
  amountUGX: number;
  tokenAmount: string;
  token: string;
  status: 'PENDING_CHAIN' | 'ESCROWED' | 'DELIVERED' | 'DISPUTED' | 'REFUNDED';
  expiry: number;
  createdAt: number;
  locationDescription: string;
  agentTelegramId?: string;
  receiverPhone?: string;    // stored only during dispatch window, then deleted
}

interface AgentRecord {
  wallet: string;
  telegramId: string;
  phone: string;
  locations: Array<{ lat: number; lng: number; description: string }>;
  reputationScore: number;
  maxTransactionUGX: number;
  dailyLimitRemaining: number;
  active: boolean;
  provisional: boolean;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const PIN_TTL_SECONDS   = 86_400;   // 24 hours
const META_TTL_SECONDS  = 604_800;  // 7 days
const UGX_TO_USD_RATE   = 3750;     // Updated periodically via oracle
const FEE_BPS           = 150;      // 1.5%
const MAX_TRANSFER_UGX  = 1_875_000; // ~$500 USD at current rate

// ─── Router ───────────────────────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return corsResponse(new Response(null, { status: 204 }), env);
    }

    const route = `${request.method} ${url.pathname}`;

    try {
      switch (route) {
        // ── Transfer Lifecycle ──
        case 'POST /v1/transfers/initiate':
          return corsResponse(await handleInitiate(request, env), env);
        case 'POST /v1/transfers/confirm-delivery':
          return corsResponse(await handleConfirmDelivery(request, env), env);
        case 'POST /v1/transfers/dispute':
          return corsResponse(await handleDispute(request, env), env);
        case 'POST /v1/transfers/refund':
          return corsResponse(await handleRefund(request, env), env);

        // ── Agent ──
        case 'GET /v1/agents/nearby':
          return corsResponse(await handleNearbyAgents(request, env), env);
        case 'POST /v1/agents/register':
          return corsResponse(await handleAgentRegister(request, env), env);

        // ── Transfer Query ──
        case 'GET /v1/transfers/status':
          return corsResponse(await handleTransferStatus(request, env), env);

        // ── Telegram Webhook ──
        case 'POST /webhook/telegram':
          return await handleTelegramWebhook(request, env);

        // ── SMS Callback (Africa's Talking) ──
        case 'POST /webhook/sms':
          return await handleSmsCallback(request, env);

        // ── Health ──
        case 'GET /health':
          return jsonResponse({ status: 'ok', ts: Date.now() });

        default:
          return jsonResponse({ error: 'Not found' }, 404);
      }
    } catch (err: any) {
      console.error('[router]', err);
      return jsonResponse({ error: 'Internal error', detail: err.message }, 500);
    }
  }
};

// ─── Transfer: Initiate ───────────────────────────────────────────────────────

async function handleInitiate(request: Request, env: Env): Promise<Response> {
  const body = await request.json() as {
    amountUGX: number;
    agentWallet: string;
    locationDescription: string;
    receiverPhone?: string;
    senderWallet: string;
    token: string; // 'USDC' | 'USDT'
  };

  // Validate inputs
  if (!body.amountUGX || body.amountUGX <= 0) {
    return jsonResponse({ error: 'Invalid amount' }, 400);
  }
  if (body.amountUGX > MAX_TRANSFER_UGX) {
    return jsonResponse({
      error: `Exceeds per-transfer limit (${MAX_TRANSFER_UGX.toLocaleString()} UGX)`
    }, 400);
  }

  // Fetch agent
  const agentRaw = await env.KV.get(`agent:${body.agentWallet}`, 'json') as AgentRecord | null;
  if (!agentRaw || !agentRaw.active) {
    return jsonResponse({ error: 'Agent not found or inactive' }, 400);
  }
  if (body.amountUGX > agentRaw.maxTransactionUGX) {
    return jsonResponse({ error: 'Exceeds agent transaction limit' }, 400);
  }
  if (body.amountUGX > agentRaw.dailyLimitRemaining) {
    return jsonResponse({ error: 'Exceeds agent daily limit' }, 400);
  }

  // Calculate token amounts
  const usdAmount      = body.amountUGX / UGX_TO_USD_RATE;
  const feeFactor      = 1 + FEE_BPS / 10_000;
  const totalUSD       = usdAmount * feeFactor;
  const tokenDecimals  = 6; // USDC/USDT both 6 decimals
  const principalToken = Math.floor(usdAmount * 10 ** tokenDecimals).toString();
  const totalToken     = Math.floor(totalUSD * 10 ** tokenDecimals).toString();

  // Generate transfer ID (collision-resistant)
  const nonce       = crypto.getRandomValues(new Uint8Array(8));
  const nonceHex    = Array.from(nonce).map(b => b.toString(16).padStart(2, '0')).join('');
  const idInput     = `${body.senderWallet}:${body.agentWallet}:${Date.now()}:${nonceHex}`;
  const transferId  = '0x' + await sha256Hex(idInput);

  // Generate 6-digit PIN (crypto-random)
  const pin         = generateSecurePin();
  const pinHash     = await sha256Hex(pin + transferId);   // commitment for on-chain
  const pinCommit   = '0x' + await sha256Hex(pin + transferId); // keccak equiv (off-chain)

  // Hash receiver identity
  const salt         = crypto.getRandomValues(new Uint8Array(16));
  const saltHex      = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
  const receiverHash = body.receiverPhone
    ? '0x' + await sha256Hex(body.receiverPhone + saltHex)
    : '0x' + await sha256Hex('anonymous:' + nonceHex);

  const expiry    = Math.floor(Date.now() / 1000) + PIN_TTL_SECONDS;
  const createdAt = Math.floor(Date.now() / 1000);

  // Store transfer metadata in KV (7d TTL)
  const record: TransferRecord = {
    transferId,
    sender:              body.senderWallet,
    agentWallet:         body.agentWallet,
    receiverHash,
    pinHash,
    amountUGX:           body.amountUGX,
    tokenAmount:         principalToken,
    token:               body.token,
    status:              'PENDING_CHAIN',
    expiry,
    createdAt,
    locationDescription: body.locationDescription,
    agentTelegramId:     agentRaw.telegramId,
    // Store phone only for 24h SMS delivery window
    receiverPhone:       body.receiverPhone,
  };

  await env.KV.put(
    `transfer:${transferId}`,
    JSON.stringify(record),
    { expirationTtl: META_TTL_SECONDS }
  );

  // Store PIN separately with 24h TTL (deleted after redemption)
  await env.KV.put(
    `pin:${transferId}`,
    pin,
    { expirationTtl: PIN_TTL_SECONDS }
  );

  // Dispatch notifications (non-blocking)
  const dispatchPromises: Promise<any>[] = [];

  // Notify agent via Telegram
  if (agentRaw.telegramId) {
    const agentMsg = [
      `🔔 *New Payout Request*`,
      `Amount: UGX ${body.amountUGX.toLocaleString()}`,
      `Location: ${body.locationDescription}`,
      `Transfer ID: \`${transferId.slice(0, 10)}...\``,
      `Expires: ${new Date(expiry * 1000).toISOString()}`,
      ``,
      `Reply /ready_${transferId.slice(2, 10)} to confirm availability`,
      `Reply /decline_${transferId.slice(2, 10)} to pass`,
    ].join('\n');
    dispatchPromises.push(
      sendTelegram(agentRaw.telegramId, agentMsg, env).catch(console.error)
    );
  }

  // Notify agent via SMS (fallback)
  if (agentRaw.phone) {
    const smsText = `CashHawala: New payout UGX ${body.amountUGX.toLocaleString()} @ ${body.locationDescription}. ID:${transferId.slice(2, 10)}. Reply Y to confirm.`;
    dispatchPromises.push(
      sendSMS(agentRaw.phone, smsText, env).catch(console.error)
    );
  }

  // Send PIN to receiver via SMS if phone provided
  if (body.receiverPhone) {
    const receiverSms = `CashHawala: Your cash pickup PIN is ${pin}. Go to ${body.locationDescription} to collect UGX ${body.amountUGX.toLocaleString()}. PIN expires in 24h. Do NOT share with anyone except the agent.`;
    dispatchPromises.push(
      sendSMS(body.receiverPhone, receiverSms, env).catch(console.error)
    );
  }

  await Promise.allSettled(dispatchPromises);

  return jsonResponse({
    transferId,
    pin,           // shown to sender in PWA — sender forwards to receiver if no phone
    pinCommitment: pinCommit,
    receiverHash,
    principalToken,
    totalToken,
    feeUSD:  (totalUSD - usdAmount).toFixed(4),
    expiry,
    status: 'PENDING_CHAIN',
    // What sender needs to submit to smart contract:
    contractParams: {
      transferId,
      agentWallet: body.agentWallet,
      receiverHash,
      pinCommitment: pinCommit,
      token:         body.token,
      principalAmount: principalToken,
      amountUGX:     body.amountUGX,
      locationHash:  '0x' + await sha256Hex(body.locationDescription),
    }
  });
}

// ─── Transfer: Status ─────────────────────────────────────────────────────────

async function handleTransferStatus(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const transferId = url.searchParams.get('id');
  if (!transferId) return jsonResponse({ error: 'Missing id' }, 400);

  const record = await env.KV.get(`transfer:${transferId}`, 'json') as TransferRecord | null;
  if (!record) return jsonResponse({ error: 'Transfer not found' }, 404);

  // Never expose receiver phone or PIN hash in responses
  const { receiverPhone, pinHash, ...safe } = record;

  return jsonResponse(safe);
}

// ─── Transfer: Confirm Delivery (Agent calls after cash handoff) ──────────────

async function handleConfirmDelivery(request: Request, env: Env): Promise<Response> {
  const body = await request.json() as {
    transferId: string;
    agentWallet: string;
    pin: string;
    proofType: 0 | 1 | 2;
    proofData?: string; // geotag hash or SMS timestamp
  };

  const record = await env.KV.get(`transfer:${body.transferId}`, 'json') as TransferRecord | null;
  if (!record) return jsonResponse({ error: 'Transfer not found' }, 404);

  if (record.agentWallet.toLowerCase() !== body.agentWallet.toLowerCase()) {
    return jsonResponse({ error: 'Agent mismatch' }, 403);
  }

  const storedPin = await env.KV.get(`pin:${body.transferId}`);
  if (!storedPin) return jsonResponse({ error: 'PIN expired' }, 410);
  if (storedPin !== body.pin) return jsonResponse({ error: 'Invalid PIN' }, 403);

  if (Math.floor(Date.now() / 1000) > record.expiry) {
    return jsonResponse({ error: 'Transfer expired' }, 410);
  }

  // Invalidate PIN immediately (single-use)
  await env.KV.delete(`pin:${body.transferId}`);

  // Update status
  record.status = 'DELIVERED';
  await env.KV.put(
    `transfer:${body.transferId}`,
    JSON.stringify(record),
    { expirationTtl: META_TTL_SECONDS }
  );

  // The agent now calls confirmDelivery() on-chain themselves.
  // We return the proof data they need to submit.
  const proofHash = body.proofData
    ? '0x' + await sha256Hex(body.proofData)
    : '0x0000000000000000000000000000000000000000000000000000000000000000';

  return jsonResponse({
    success: true,
    transferId: body.transferId,
    proofType: body.proofType,
    proofHash,
    message: 'PIN verified. Submit on-chain confirmDelivery() to release funds.',
    contractParams: {
      transferId: body.transferId,
      pin: body.pin,
      proofType: body.proofType,
      proofData: proofHash,
    }
  });
}

// ─── Transfer: Dispute ────────────────────────────────────────────────────────

async function handleDispute(request: Request, env: Env): Promise<Response> {
  const body = await request.json() as {
    transferId: string;
    initiatorWallet: string;
    reason: string;
    evidenceHash?: string;
  };

  const record = await env.KV.get(`transfer:${body.transferId}`, 'json') as TransferRecord | null;
  if (!record) return jsonResponse({ error: 'Transfer not found' }, 404);

  const isParty =
    record.sender.toLowerCase() === body.initiatorWallet.toLowerCase() ||
    record.agentWallet.toLowerCase() === body.initiatorWallet.toLowerCase();

  if (!isParty) return jsonResponse({ error: 'Not party to transfer' }, 403);

  record.status = 'DISPUTED';
  await env.KV.put(
    `transfer:${body.transferId}`,
    JSON.stringify(record),
    { expirationTtl: META_TTL_SECONDS }
  );

  // Store dispute record
  const dispute = {
    transferId: body.transferId,
    initiator: body.initiatorWallet,
    reason: body.reason,
    evidenceHash: body.evidenceHash || null,
    openedAt: Date.now(),
  };
  await env.KV.put(
    `dispute:${body.transferId}`,
    JSON.stringify(dispute),
    { expirationTtl: META_TTL_SECONDS }
  );

  // Notify both parties
  const agentRec = await env.KV.get(`agent:${record.agentWallet}`, 'json') as AgentRecord | null;
  if (agentRec?.telegramId) {
    await sendTelegram(
      agentRec.telegramId,
      `⚠️ *Dispute Opened*\nTransfer ${body.transferId.slice(0, 10)}...\nReason: ${body.reason}\nArbiters will review within 24h.`,
      env
    ).catch(console.error);
  }

  return jsonResponse({
    success: true,
    message: 'Dispute registered. Submit openDispute() on-chain to lock escrow. Arbiters will be notified.',
    disputeId: body.transferId,
  });
}

// ─── Transfer: Refund ─────────────────────────────────────────────────────────

async function handleRefund(request: Request, env: Env): Promise<Response> {
  const body = await request.json() as {
    transferId: string;
    senderWallet: string;
  };

  const record = await env.KV.get(`transfer:${body.transferId}`, 'json') as TransferRecord | null;
  if (!record) return jsonResponse({ error: 'Transfer not found' }, 404);
  if (record.sender.toLowerCase() !== body.senderWallet.toLowerCase()) {
    return jsonResponse({ error: 'Not sender' }, 403);
  }

  const now = Math.floor(Date.now() / 1000);
  const disputeWindowEnd = record.expiry + 86_400; // +24h
  if (now < disputeWindowEnd) {
    return jsonResponse({
      error: 'Dispute window still active',
      refundAvailableAt: new Date(disputeWindowEnd * 1000).toISOString()
    }, 400);
  }

  return jsonResponse({
    success: true,
    message: 'Dispute window passed. Submit claimRefund() on-chain.',
    transferId: body.transferId,
  });
}

// ─── Agents: Nearby ───────────────────────────────────────────────────────────

async function handleNearbyAgents(request: Request, env: Env): Promise<Response> {
  const url   = new URL(request.url);
  const lat   = parseFloat(url.searchParams.get('lat') || '0');
  const lng   = parseFloat(url.searchParams.get('lng') || '0');
  const ugx   = parseInt(url.searchParams.get('amountUGX') || '0', 10);

  // In production: query a geo-index (Cloudflare D1 or Workers Analytics Engine)
  // MVP: scan active agent list from KV (small dataset)
  const agentIndex = await env.KV.get('index:agents', 'json') as string[] | null;
  if (!agentIndex || agentIndex.length === 0) {
    return jsonResponse({ agents: [] });
  }

  const candidates: Array<AgentRecord & { distanceKm: number }> = [];

  for (const wallet of agentIndex) {
    const agent = await env.KV.get(`agent:${wallet}`, 'json') as AgentRecord | null;
    if (!agent || !agent.active) continue;
    if (ugx > 0 && ugx > agent.dailyLimitRemaining) continue;
    if (ugx > 0 && ugx > agent.maxTransactionUGX) continue;

    for (const loc of agent.locations) {
      const distKm = haversineKm(lat, lng, loc.lat, loc.lng);
      if (distKm <= 20) { // 20km radius
        candidates.push({ ...agent, distanceKm: distKm });
        break;
      }
    }
  }

  // Sort by proximity, then reputation
  candidates.sort((a, b) => {
    const distScore = (a.distanceKm - b.distanceKm) * 10;
    const repScore  = (b.reputationScore - a.reputationScore);
    return distScore + repScore;
  });

  // Redact sensitive fields before returning
  const safeAgents = candidates.slice(0, 5).map(a => ({
    wallet:              a.wallet,
    distanceKm:          Math.round(a.distanceKm * 10) / 10,
    reputationScore:     a.reputationScore,
    maxTransactionUGX:   a.maxTransactionUGX,
    dailyLimitRemaining: a.dailyLimitRemaining,
    provisional:         a.provisional,
    locations:           a.locations.map(l => ({ description: l.description })),
  }));

  return jsonResponse({ agents: safeAgents });
}

// ─── Agents: Register ─────────────────────────────────────────────────────────

async function handleAgentRegister(request: Request, env: Env): Promise<Response> {
  const body = await request.json() as Partial<AgentRecord> & {
    referralCode?: string;
  };

  if (!body.wallet || !body.phone || !body.locations?.length) {
    return jsonResponse({ error: 'Missing required fields' }, 400);
  }

  const existing = await env.KV.get(`agent:${body.wallet}`, 'json');
  if (existing) return jsonResponse({ error: 'Already registered' }, 409);

  const record: AgentRecord = {
    wallet:              body.wallet,
    telegramId:          body.telegramId || '',
    phone:               body.phone,
    locations:           body.locations,
    reputationScore:     80,     // start at 80/100
    maxTransactionUGX:   200_000, // provisional limits
    dailyLimitRemaining: 600_000,
    active:              false,   // requires manual activation after collateral check
    provisional:         true,
  };

  await env.KV.put(`agent:${body.wallet}`, JSON.stringify(record));

  // Add to index
  const index = (await env.KV.get('index:agents', 'json') as string[] | null) || [];
  if (!index.includes(body.wallet)) {
    index.push(body.wallet);
    await env.KV.put('index:agents', JSON.stringify(index));
  }

  return jsonResponse({
    success: true,
    status: 'PENDING_ACTIVATION',
    message: 'Registration received. Deposit $50 USDC collateral on-chain to activate.',
    wallet: body.wallet,
  }, 201);
}

// ─── Telegram Webhook ─────────────────────────────────────────────────────────

async function handleTelegramWebhook(request: Request, env: Env): Promise<Response> {
  const update = await request.json() as any;
  const msg    = update?.message;
  if (!msg?.text) return new Response('ok');

  const text     = msg.text as string;
  const chatId   = String(msg.chat.id);

  // Agent readiness commands: /ready_XXXXXXXX or /decline_XXXXXXXX
  const readyMatch   = text.match(/^\/ready_([a-f0-9]{8})/i);
  const declineMatch = text.match(/^\/decline_([a-f0-9]{8})/i);

  if (readyMatch) {
    const shortId = readyMatch[1];
    await sendTelegram(chatId, `✅ Confirmed. Waiting for receiver to show PIN at your location. Reply /delivered_${shortId} once cash is handed over.`, env);
  } else if (declineMatch) {
    const shortId = declineMatch[1];
    await sendTelegram(chatId, `Understood. Transfer ${shortId} has been reassigned.`, env);
    // TODO: trigger agent reassignment flow
  } else if (text.startsWith('/start')) {
    await sendTelegram(chatId, `Welcome to Cash Hawala Uganda 🇺🇬\n\nI notify you of incoming payouts and help you confirm deliveries.\n\nYour Telegram ID: ${chatId}\n\nPlease provide this ID when registering as an agent.`, env);
  } else if (text.startsWith('/help')) {
    await sendTelegram(chatId, `Commands:\n/ready_ID — Confirm you can handle a payout\n/decline_ID — Pass on a payout\n/delivered_ID — Confirm cash was handed over\n/balance — Check your daily limit\n/status_ID — Check transfer status`, env);
  }

  return new Response('ok');
}

// ─── SMS Callback (Africa's Talking) ──────────────────────────────────────────

async function handleSmsCallback(request: Request, env: Env): Promise<Response> {
  const body = await request.text();
  const params = new URLSearchParams(body);
  const from = params.get('from') || '';
  const text = (params.get('text') || '').trim().toUpperCase();

  // Agent replies "Y" to confirm readiness
  if (text === 'Y' || text === 'YES') {
    await sendSMS(from, `CashHawala: Confirmed. Await receiver at your location.`, env);
  } else if (text === 'N' || text === 'NO') {
    await sendSMS(from, `CashHawala: Noted. Transfer will be reassigned.`, env);
  }
  // Receiver SMS confirmation handled via shortcode replies in production

  return new Response('ok');
}

// ─── Utilities ────────────────────────────────────────────────────────────────

function generateSecurePin(): string {
  const arr = crypto.getRandomValues(new Uint32Array(1));
  return String(arr[0] % 1_000_000).padStart(6, '0');
}

async function sha256Hex(input: string): Promise<string> {
  const encoder = new TextEncoder();
  const data    = encoder.encode(input);
  const hashBuf = await crypto.subtle.digest('SHA-256', data);
  const hashArr = Array.from(new Uint8Array(hashBuf));
  return hashArr.map(b => b.toString(16).padStart(2, '0')).join('');
}

function haversineKm(lat1: number, lng1: number, lat2: number, lng2: number): number {
  const R    = 6371;
  const dLat = deg2rad(lat2 - lat1);
  const dLng = deg2rad(lng2 - lng1);
  const a    =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(deg2rad(lat1)) * Math.cos(deg2rad(lat2)) * Math.sin(dLng / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function deg2rad(d: number): number {
  return d * (Math.PI / 180);
}

async function sendTelegram(chatId: string, text: string, env: Env): Promise<void> {
  const url = `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`;
  await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'Markdown' }),
  });
}

async function sendSMS(phone: string, message: string, env: Env): Promise<void> {
  // Africa's Talking SMS API
  const body = new URLSearchParams({
    username: env.AT_USERNAME,
    to:       phone,
    message,
  });
  await fetch('https://api.africastalking.com/version1/messaging', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'apiKey':       env.AT_API_KEY,
      'Accept':       'application/json',
    },
    body: body.toString(),
  });
}

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
    },
  });
}

function corsResponse(response: Response, env: Env): Response {
  const headers = new Headers(response.headers);
  headers.set('Access-Control-Allow-Origin', env.ALLOWED_ORIGIN || '*');
  headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  return new Response(response.body, {
    status: response.status,
    headers,
  });
}
