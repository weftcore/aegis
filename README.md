# @weftcore/aegis

🛡️ Universal client-side runtime security guard, anti-reverse-engineering, and anti-tamper suite.

Zero hardcoded domains. Zero dependencies. Works with **any** web app, framework, and cloud deployment.

---

## What It Protects Against

| Threat | Module | How It Works |
|---|---|---|
| **DevTools Inspection** | Multi-Vector Anti-Debug | Docked dimension differential checks (`outerWidth - innerWidth > 160`), Web Worker heartbeat monitor, and active timing traps. |
| **Iframe Prototype Leaks** | Iframe Prototype Shield | Intercepts `document.createElement('iframe')` and poisons clean prototype extraction to prevent bypasses. |
| **Token Theft & Memory Dumps** | Non-Extractable Key Enclave | Uses true non-extractable WebCrypto keys (`extractable: false`) stored in IndexedDB with 96-bit random IVs and AES-GCM (256-bit). |
| **API Replay & Mass Scraping** | Signer & Micro Proof-of-Work | Signs requests with HMAC-SHA256 and client-side micro-PoW hashcash puzzles that throttle automated bots. |
| **Stealth Bots & Headless Scrapers** | Hardware & DSP Fingerprint | AudioContext floating-point DSP variance, Canvas 2D winding geometry, WebGL software rasterizer & shader precision analysis. |
| **AI Reconnaissance & Scanners** | Multi-Scope Honeypots | Global window & hidden DOM decoy traps returning synthetic poisoning payloads to waste scanner tokens and alert telemetry. |
| **Unauthorized Framing** | Frame Guard | Strict ancestor and document.referrer validation with automatic DOM wiping and redirect. |
| **Runtime Monkey-Patching** | Deep Freeze | Recursively freezes objects and prototypes to prevent method overrides. |
| **Console Data Harvesting** | Console Silencer & Plugin | Multi-line balanced parenthesis stripper and production console silencer. |

---

## Installation

```bash
npm install @weftcore/aegis
```

---

## Quick Start (Runtime Shield)

Initialize the guard at the top of your app entry point (`main.ts` / `index.tsx` / `App.tsx`):

```typescript
import { initSecurityGuard } from '@weftcore/aegis';

initSecurityGuard({
  allowedOrigins: /^https:\/\/([a-zA-Z0-9-]+\.)?example\.com$/,
  unauthorizedRedirectUrl: 'https://example.com',
  onViolation: (type, detail) => {
    console.error('Security alert:', type, detail);
  },
});
```

---

## Advanced Upgrades & Features

### 1. Encrypted Storage Enclave (`secureStorage`)
Protect sensitive JWT tokens from being read in plain text via DevTools:

```typescript
import { secureStorage, secureSession } from '@weftcore/aegis';

// Stored as AES-GCM encrypted ciphertext in localStorage
await secureStorage.setItem('TOKEN', 'jwt-token-value');

// Decrypted seamlessly
const token = await secureStorage.getItem('TOKEN');
```

---

### 2. Dynamic Request Signing (Anti-Tamper & Anti-Replay)
Sign outgoing API requests so they cannot be copied into curl, Postman, or replayed by attackers:

```typescript
import { createSignedFetcher } from '@weftcore/aegis';

const secureFetch = createSignedFetcher(fetch, {
  secretKey: 'your-shared-client-salt',
  headerPrefix: 'X-Aegis',
});

// Outgoing request automatically has X-Aegis-Timestamp, Nonce, and Signature
const response = await secureFetch('/api/protected-endpoint', {
  method: 'POST',
  body: JSON.stringify({ action: 'checkout' }),
});
```

#### Server-Side Verifier (Cloudflare Pages Functions / Workers / Node.js)

```typescript
import { verifySignature } from '@weftcore/aegis';

const isValid = await verifySignature(
  request.method,
  request.url,
  bodyText,
  request.headers,
  { secretKey: 'your-shared-client-salt' }
);

if (!isValid) {
  return new Response('Unauthorized Request', { status: 401 });
}
```

---

### 3. Stealth Bot & Headless Detection

```typescript
import { detectStealthBot } from '@weftcore/aegis';

const { isBot, score, reasons } = detectStealthBot();
if (isBot) {
  // Take defensive action (e.g., render captcha or block)
}
```

---

### 4. Bundler Plugin (`@weftcore/aegis/plugin`)
Integrate into `vite.config.ts` or `rspack.config.mjs`:

```typescript
import { aegisPlugin } from '@weftcore/aegis/plugin';

export default {
  plugins: [
    aegisPlugin({
      dropConsole: true,
      injectPreamble: false,
    }),
  ],
};
```

---

## API Reference

### `initSecurityGuard(options?)`

| Option | Type | Default | Description |
|---|---|---|---|
| `allowedOrigins` | `RegExp \| string[]` | — | Permitted iframe parent origins |
| `unauthorizedRedirectUrl` | `string` | — | Redirect URL when framed by unauthorized parent |
| `allowLocalhostInDev` | `boolean` | `true` | Allows `localhost` and `127.0.0.1` in development mode |
| `silenceConsole` | `boolean` | `true` | Silences console outputs in production |
| `antiDebug` | `boolean` | `true` | Triggers active debugger trap loop |
| `antiDebugIntervalMs` | `number` | `2000` | Debugger check loop frequency |
| `antiSourceExtraction` | `boolean` | `true` | Blocks REA and AI code extraction tools |
| `antiHeadless` | `boolean` | `true` | Detects automation bots and software GPUs |
| `antiAiScanners` | `boolean` | `true` | Deploys honeypot traps for AI recon scanners |
| `blockDevShortcuts` | `boolean` | `true` | Intercepts F12, Ctrl+Shift+I/J/C, and right-click |
| `freezeTargets` | `object[]` | — | Objects to deep-freeze |
| `onViolation` | `(type, detail?) => void` | — | Callback invoked on security breaches |

---

## License

MIT © [weftcore](https://github.com/weftcore)
