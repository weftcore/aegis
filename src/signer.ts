/**
 * @weftcore/aegis - Dynamic Request Signing & Proof-of-Work (Anti-Tamper & Anti-Replay)
 * 
 * Provides:
 * 1. HMAC-SHA256 canonical request signing (Method + Canonical Path + Timestamp + Nonce + BodyHash).
 * 2. Client-side Micro Proof-of-Work (PoW) challenge solver (defeats mass automated scrapers).
 * 3. Unified fetch wrapper (`createSignedFetcher`).
 * 4. Server-side verification helper (`verifySignature`) for Cloudflare Workers, Pages Functions, and Node.js.
 */

declare const crypto: Crypto;

export interface SignerOptions {
  secretKey: string;
  headerPrefix?: string; // Default: 'X-Aegis'
  maxClockSkewSec?: number; // Default: 300 (5 minutes)
  powDifficulty?: number; // Optional: Leading zeros required in hashcash PoW (e.g. 2, 3, or 4)
}

export interface SignatureHeaders {
  [header: string]: string;
}

/**
 * Solves a micro Proof-of-Work (Hashcash) challenge in browser JavaScript.
 * Finds a numeric nonce such that SHA-256(seed + nonce) starts with `difficulty` zeros.
 */
async function solveProofOfWork(seed: string, difficulty: number): Promise<{ nonce: string; hash: string }> {
  if (difficulty <= 0) return { nonce: '0', hash: '' };

  const targetPrefix = '0'.repeat(difficulty);
  const enc = new TextEncoder();
  let nonceNum = 0;

  while (nonceNum < 500_000) {
    const candidate = `${seed}:${nonceNum}`;
    const hashBuffer = await crypto.subtle.digest('SHA-256', enc.encode(candidate));
    const hashHex = Array.from(new Uint8Array(hashBuffer))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    if (hashHex.startsWith(targetPrefix)) {
      return { nonce: String(nonceNum), hash: hashHex };
    }
    nonceNum++;
  }

  return { nonce: '0', hash: '' };
}

/**
 * Verifies a Proof-of-Work solution.
 */
async function verifyProofOfWork(seed: string, nonce: string, difficulty: number): Promise<boolean> {
  if (difficulty <= 0) return true;
  const targetPrefix = '0'.repeat(difficulty);
  const enc = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest('SHA-256', enc.encode(`${seed}:${nonce}`));
  const hashHex = Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return hashHex.startsWith(targetPrefix);
}

/**
 * Computes an HMAC-SHA256 signature for an HTTP request with optional PoW nonces.
 */
export async function signRequest(
  method: string,
  url: string,
  body: string | undefined | null,
  options: SignerOptions
): Promise<SignatureHeaders> {
  const prefix = options.headerPrefix || 'X-Aegis';
  const timestamp = Math.floor(Date.now() / 1000).toString();

  // High-entropy 128-bit random nonce
  const rawNonce = crypto.getRandomValues(new Uint8Array(16));
  const nonce = Array.from(rawNonce)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  const parsedUrl = new URL(url, typeof window !== 'undefined' ? window.location.origin : 'http://localhost');
  const pathAndQuery = parsedUrl.pathname + parsedUrl.search;
  const bodyString = body ? String(body) : '';

  // Canonical body hash
  const bodyHashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(bodyString));
  const bodyHash = Array.from(new Uint8Array(bodyHashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  // Optional Micro Proof-of-Work
  let powNonce = '';
  if (options.powDifficulty && options.powDifficulty > 0) {
    const powSeed = `${method.toUpperCase()}:${pathAndQuery}:${timestamp}:${nonce}`;
    const solved = await solveProofOfWork(powSeed, options.powDifficulty);
    powNonce = solved.nonce;
  }

  // Canonical representation:
  // METHOD\nPATH_AND_QUERY\nTIMESTAMP\nNONCE\nBODY_HASH\nPOW_NONCE
  const canonical = [
    method.toUpperCase(),
    pathAndQuery,
    timestamp,
    nonce,
    bodyHash,
    powNonce,
  ].join('\n');

  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(options.secretKey),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const sigBuffer = await crypto.subtle.sign('HMAC', key, enc.encode(canonical));
  const signature = Array.from(new Uint8Array(sigBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  const headers: SignatureHeaders = {
    [`${prefix}-Timestamp`]: timestamp,
    [`${prefix}-Nonce`]: nonce,
    [`${prefix}-Signature`]: signature,
  };

  if (powNonce) {
    headers[`${prefix}-PoW`] = powNonce;
  }

  return headers;
}

/**
 * Wraps global fetch to automatically sign all outgoing API requests.
 */
export function createSignedFetcher(
  fetchFn: typeof fetch,
  options: SignerOptions
): typeof fetch {
  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const method = init?.method || (typeof input === 'object' && 'method' in input ? input.method : 'GET');
    const body = init?.body && typeof init.body === 'string' ? init.body : undefined;

    const signatureHeaders = await signRequest(method, url, body, options);

    const mergedHeaders = new Headers(init?.headers);
    for (const [k, v] of Object.entries(signatureHeaders)) {
      mergedHeaders.set(k, v);
    }

    return fetchFn(input, {
      ...init,
      headers: mergedHeaders,
    });
  };
}

/**
 * Server-side verifier for Cloudflare Workers, Pages Functions, Fastify, Express, and Node.js.
 */
export async function verifySignature(
  method: string,
  url: string,
  body: string | undefined | null,
  headers: Headers | Record<string, string | undefined>,
  options: SignerOptions
): Promise<{ valid: boolean; reason?: string }> {
  const prefix = options.headerPrefix || 'X-Aegis';
  const getHeader = (name: string): string | null => {
    if (headers instanceof Headers) return headers.get(name);
    return headers[name] || headers[name.toLowerCase()] || null;
  };

  const timestamp = getHeader(`${prefix}-Timestamp`);
  const nonce = getHeader(`${prefix}-Nonce`);
  const signature = getHeader(`${prefix}-Signature`);
  const powNonce = getHeader(`${prefix}-PoW`) || '';

  if (!timestamp || !nonce || !signature) {
    return { valid: false, reason: 'missing-signature-headers' };
  }

  // 1. Clock skew check
  const now = Math.floor(Date.now() / 1000);
  const reqTime = parseInt(timestamp, 10);
  const maxSkew = options.maxClockSkewSec ?? 300;
  if (isNaN(reqTime) || Math.abs(now - reqTime) > maxSkew) {
    return { valid: false, reason: 'timestamp-skew-exceeded' };
  }

  const parsedUrl = new URL(url, 'http://localhost');
  const pathAndQuery = parsedUrl.pathname + parsedUrl.search;
  const bodyString = body ? String(body) : '';

  // 2. Proof-of-Work check if required
  if (options.powDifficulty && options.powDifficulty > 0) {
    const powSeed = `${method.toUpperCase()}:${pathAndQuery}:${timestamp}:${nonce}`;
    const powValid = await verifyProofOfWork(powSeed, powNonce, options.powDifficulty);
    if (!powValid) {
      return { valid: false, reason: 'invalid-proof-of-work' };
    }
  }

  // 3. Body hash
  const bodyHashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(bodyString));
  const bodyHash = Array.from(new Uint8Array(bodyHashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  // 4. Reconstruct canonical string
  const canonical = [
    method.toUpperCase(),
    pathAndQuery,
    timestamp,
    nonce,
    bodyHash,
    powNonce,
  ].join('\n');

  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(options.secretKey),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );

  const sigBytes = new Uint8Array(
    (signature.match(/[\da-f]{2}/gi) || []).map((h) => parseInt(h, 16))
  );

  const isValid = await crypto.subtle.verify('HMAC', key, sigBytes, enc.encode(canonical));
  return { valid: isValid, reason: isValid ? undefined : 'signature-mismatch' };
}
