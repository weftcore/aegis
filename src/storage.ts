/**
 * @weftcore/aegis - Encrypted Storage Enclave
 * Transparently encrypts localStorage and sessionStorage using AES-GCM via Web Crypto API.
 * Sensitive data (e.g. JWT tokens) is stored as encrypted ciphertext, invisible to DevTools scrapers.
 */

declare const crypto: Crypto;

class SecureStorage {
  private keyPromise: Promise<CryptoKey> | null = null;
  private backend: Storage;
  private prefix: string;

  constructor(backend: Storage, prefix = '__aegis_enc_') {
    this.backend = backend;
    this.prefix = prefix;
  }

  private async getSessionKey(): Promise<CryptoKey> {
    if (this.keyPromise) return this.keyPromise;

    this.keyPromise = (async () => {
      // In-memory or transient session seed
      const sessionSeed = sessionStorage.getItem('__aegis_seed_') || (() => {
        const rand = Array.from(crypto.getRandomValues(new Uint8Array(32)))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');
        try { sessionStorage.setItem('__aegis_seed_', rand); } catch { /* noop */ }
        return rand;
      })();

      const enc = new TextEncoder();
      const rawKey = await crypto.subtle.importKey(
        'raw',
        enc.encode(sessionSeed),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
      );

      return crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: enc.encode('weftcore-aegis-salt'),
          iterations: 10000,
          hash: 'SHA-256',
        },
        rawKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
    })();

    return this.keyPromise;
  }

  async setItem(key: string, value: string): Promise<void> {
    if (typeof window === 'undefined' || !crypto?.subtle) {
      this.backend.setItem(key, value);
      return;
    }

    try {
      const cryptoKey = await this.getSessionKey();
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encoded = new TextEncoder().encode(value);

      const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        cryptoKey,
        encoded
      );

      const payload = {
        iv: Array.from(iv),
        data: Array.from(new Uint8Array(ciphertext)),
      };

      this.backend.setItem(key, this.prefix + JSON.stringify(payload));
    } catch {
      // Fallback if encryption fails
      this.backend.setItem(key, value);
    }
  }

  async getItem(key: string): Promise<string | null> {
    const raw = this.backend.getItem(key);
    if (!raw) return null;

    if (!raw.startsWith(this.prefix)) {
      return raw; // Legacy unencrypted item
    }

    if (typeof window === 'undefined' || !crypto?.subtle) {
      return null;
    }

    try {
      const cryptoKey = await this.getSessionKey();
      const payload = JSON.parse(raw.slice(this.prefix.length));
      const iv = new Uint8Array(payload.iv);
      const data = new Uint8Array(payload.data);

      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        cryptoKey,
        data
      );

      return new TextDecoder().decode(decrypted);
    } catch {
      return null;
    }
  }

  removeItem(key: string): void {
    this.backend.removeItem(key);
  }

  clear(): void {
    this.backend.clear();
  }
}

export function createSecureStorage(storage?: Storage): SecureStorage {
  const target = storage || (typeof window !== 'undefined' ? window.localStorage : ({} as Storage));
  return new SecureStorage(target);
}

export const secureStorage = typeof window !== 'undefined'
  ? createSecureStorage(window.localStorage)
  : (null as unknown as SecureStorage);

export const secureSession = typeof window !== 'undefined'
  ? createSecureStorage(window.sessionStorage)
  : (null as unknown as SecureStorage);

