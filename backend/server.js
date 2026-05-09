const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { URL } = require('node:url');

const HOST = process.env.HOST || '0.0.0.0';
const PORT = Number(process.env.PORT || 8787);
const MAX_BODY_BYTES = 1024 * 1024;
const MESSAGE_TTL_MS = 24 * 60 * 60 * 1000;

const ROOT_DIR = path.resolve(__dirname, '..');
const INDEX_FILE = path.join(ROOT_DIR, 'index.html');

let nextMessageId = 1;
const encryptedStore = [];
const keyRegistry = new Map();

function setCorsHeaders(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

function sendJson(res, statusCode, payload) {
  setCorsHeaders(res);
  res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

function isValidCode(value) {
  return typeof value === 'string' && /^\d{12}$/.test(value);
}

function isBase64(value) {
  return typeof value === 'string' && /^[A-Za-z0-9+/=]+$/.test(value);
}

function collectJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';

    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > MAX_BODY_BYTES) {
        reject(new Error('Payload too large'));
        req.destroy();
      }
    });

    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });

    req.on('error', (err) => reject(err));
  });
}

function cleanupExpiredMessages() {
  const now = Date.now();
  let shiftCount = 0;
  for (const msg of encryptedStore) {
    if ((now - msg.createdAt) > MESSAGE_TTL_MS) {
      shiftCount += 1;
    } else {
      break;
    }
  }
  if (shiftCount > 0) {
    encryptedStore.splice(0, shiftCount);
  }
}

function validateEnvelope(envelope) {
  if (!envelope || typeof envelope !== 'object') {
    return 'envelope is required';
  }

  const { version, alg, senderEphemeralPubKey, iv, ciphertext } = envelope;

  if (version !== '1') return 'unsupported envelope version';
  if (alg !== 'ECDH-P256/AES-256-GCM') return 'unsupported algorithm';
  if (!isBase64(senderEphemeralPubKey || '')) return 'senderEphemeralPubKey must be base64';
  if (!isBase64(iv || '')) return 'iv must be base64';
  if (!isBase64(ciphertext || '')) return 'ciphertext must be base64';
  if ((senderEphemeralPubKey || '').length > 300) return 'senderEphemeralPubKey too long';
  if ((iv || '').length > 100) return 'iv too long';
  if ((ciphertext || '').length > 20000) return 'ciphertext too long';
  return null;
}

async function handlePublishKey(req, res) {
  let payload;
  try {
    payload = await collectJsonBody(req);
  } catch (error) {
    return sendJson(res, 400, { ok: false, error: error.message });
  }

  const subscriberCode = String(payload.subscriberCode || '');
  const publicKey = String(payload.publicKey || '');

  if (!isValidCode(subscriberCode)) {
    return sendJson(res, 400, { ok: false, error: 'subscriberCode must be 12 digits' });
  }

  if (!isBase64(publicKey) || publicKey.length > 300) {
    return sendJson(res, 400, { ok: false, error: 'publicKey must be base64 SPKI' });
  }

  keyRegistry.set(subscriberCode, {
    publicKey,
    updatedAt: Date.now(),
  });

  return sendJson(res, 200, {
    ok: true,
    subscriberCode,
    updatedAt: keyRegistry.get(subscriberCode).updatedAt,
  });
}

function handleGetKey(reqUrl, res) {
  const subscriberCode = String(reqUrl.searchParams.get('subscriberCode') || '');
  if (!isValidCode(subscriberCode)) {
    return sendJson(res, 400, { ok: false, error: 'subscriberCode must be 12 digits' });
  }

  const row = keyRegistry.get(subscriberCode);
  if (!row) {
    return sendJson(res, 404, { ok: false, error: 'public key not found for subscriber' });
  }

  return sendJson(res, 200, {
    ok: true,
    subscriberCode,
    publicKey: row.publicKey,
    updatedAt: row.updatedAt,
  });
}

async function handleSendMessage(req, res) {
  let payload;
  try {
    payload = await collectJsonBody(req);
  } catch (error) {
    return sendJson(res, 400, { ok: false, error: error.message });
  }

  const senderCode = String(payload.senderCode || '');
  const recipientCode = String(payload.recipientCode || '');
  const envelope = payload.envelope;

  if (!isValidCode(senderCode) || !isValidCode(recipientCode)) {
    return sendJson(res, 400, { ok: false, error: 'senderCode and recipientCode must be 12 digits' });
  }

  const envelopeError = validateEnvelope(envelope);
  if (envelopeError) {
    return sendJson(res, 400, { ok: false, error: envelopeError });
  }

  cleanupExpiredMessages();

  const record = {
    id: nextMessageId++,
    senderCode,
    recipientCode,
    envelope,
    createdAt: Date.now(),
  };

  encryptedStore.push(record);

  return sendJson(res, 200, {
    ok: true,
    messageId: record.id,
    queuedAt: record.createdAt,
    storedAs: 'ciphertext-only envelope',
  });
}

function handleInbox(reqUrl, res) {
  const recipientCode = String(reqUrl.searchParams.get('recipientCode') || '');
  const afterId = Number(reqUrl.searchParams.get('afterId') || 0);

  if (!isValidCode(recipientCode)) {
    return sendJson(res, 400, { ok: false, error: 'recipientCode must be 12 digits' });
  }

  cleanupExpiredMessages();

  const inbox = [];
  for (const msg of encryptedStore) {
    if (msg.recipientCode !== recipientCode || msg.id <= afterId) {
      continue;
    }

    inbox.push({
      id: msg.id,
      senderCode: msg.senderCode,
      envelope: msg.envelope,
      createdAt: msg.createdAt,
    });
  }

  return sendJson(res, 200, {
    ok: true,
    recipientCode,
    afterId,
    count: inbox.length,
    messages: inbox,
  });
}

function serveIndex(res) {
  fs.readFile(INDEX_FILE, 'utf8', (err, html) => {
    if (err) {
      return sendJson(res, 500, { ok: false, error: 'Cannot read index.html' });
    }
    setCorsHeaders(res);
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
  });
}

const server = http.createServer(async (req, res) => {
  const reqUrl = new URL(req.url || '/', `http://${req.headers.host || `${HOST}:${PORT}`}`);

  if (req.method === 'OPTIONS') {
    setCorsHeaders(res);
    res.writeHead(204);
    return res.end();
  }

  if (req.method === 'GET' && (reqUrl.pathname === '/' || reqUrl.pathname === '/index.html')) {
    return serveIndex(res);
  }

  if (req.method === 'GET' && reqUrl.pathname === '/api/health') {
    return sendJson(res, 200, {
      ok: true,
      service: '3NIGMA backend',
      privacyMode: 'E2EE ciphertext-only relay',
      time: Date.now(),
      storedMessages: encryptedStore.length,
      knownSubscribers: keyRegistry.size,
    });
  }

  if (req.method === 'POST' && reqUrl.pathname === '/api/keys/publish') {
    return handlePublishKey(req, res);
  }

  if (req.method === 'GET' && reqUrl.pathname === '/api/keys/get') {
    return handleGetKey(reqUrl, res);
  }

  if (req.method === 'POST' && reqUrl.pathname === '/api/messages/send') {
    return handleSendMessage(req, res);
  }

  if (req.method === 'GET' && reqUrl.pathname === '/api/messages/inbox') {
    return handleInbox(reqUrl, res);
  }

  return sendJson(res, 404, { ok: false, error: 'Not found' });
});

server.listen(PORT, HOST, () => {
  console.log(`3NIGMA backend is running on http://${HOST}:${PORT}`);
  console.log('Privacy mode: server relays ciphertext only and cannot decrypt messages.');
});
