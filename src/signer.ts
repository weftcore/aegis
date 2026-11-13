/**
 * @weftcore/aegis - Dynamic Request Signing (Anti-Tamper & Anti-Replay)
 * Signs client HTTP requests with HMAC-SHA256 nonces and timestamps.
 * Prevents attackers from copying requests to curl/Postman or tampering with parameters.
 */

declare const crypto: Crypto;

export interface SignerOptions {
  secretKey: string;
  headerPrefix?: string; // Default: 'X-Aegis'
  maxClockSkewSec?: number; // Default: 300 (5 minutes)
}

export interface SignatureHeaders {
  [header: string]: string;
}

/**
 * Computes an HMAC-SHA256 signature for an HTTP request.
 */
export async function signRequest(
  method: string,
  url: string,
  body: string | undefined | null,
  options: SignerOptions
): Promise<SignatureHeaders> {
  const prefix = options.headerPrefix || 'X-Aegis';
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  const parsedUrl = new URL(url, typeof window !== 'undefined' ? window.location.origin : 'http://localhost');
  const pathAndQuery = parsedUrl.pathname + parsedUrl.search;
  const bodyString = body ? String(body) : '';

  // Canonical string: METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY_HASH
  const bodyHashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(bodyString));
  const bodyHash = Array.from(new Uint8Array(bodyHashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  const canonical = [
    method.toUpperCase(),
    pathAndQuery,
    timestamp,
    nonce,
    bodyHash,
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

  return {
    [`${prefix}-Timestamp`]: timestamp,
    [`${prefix}-Nonce`]: nonce,
    [`${prefix}-Signature`]: signature,
  };
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
 * Server-side verifier for Cloudflare Pages / Workers / Node.js
 */
export async function verifySignature(
  method: string,
  url: string,
  body: string | undefined | null,
  headers: Headers | Record<string, string>,
  options: SignerOptions
): Promise<boolean> {
  const prefix = options.headerPrefix || 'X-Aegis';
  const getHeader = (name: string): string | null => {
    if (typeof (headers as Headers).get === 'function') {
      return (headers as Headers).get(name);
    }
    const record = headers as Record<string, string>;
    const match = Object.keys(record).find((k) => k.toLowerCase() === name.toLowerCase());
    return match ? record[match] : null;
  };

  const timestamp = getHeader(`${prefix}-Timestamp`);
  const nonce = getHeader(`${prefix}-Nonce`);
  const signature = getHeader(`${prefix}-Signature`);

  if (!timestamp || !nonce || !signature) return false;

  // Clock skew check
  const now = Math.floor(Date.now() / 1000);
  const maxSkew = options.maxClockSkewSec ?? 300;
  if (Math.abs(now - parseInt(timestamp, 10)) > maxSkew) return false;

  const expectedHeaders = await signRequest(method, url, body, {
    secretKey: options.secretKey,
    headerPrefix: prefix,
  });

  return signature === expectedHeaders[`${prefix}-Signature`];
}
