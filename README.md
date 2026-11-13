# @weftcore/aegis

🛡️ Universal client-side runtime security guard, anti-reverse-engineering, and anti-tamper suite.

Zero hardcoded domains. Zero dependencies. Works with **any** web app, framework, and cloud deployment.

---

## What It Protects Against

| Threat | Module | How It Works |
|---|---|---|
| **REA / AI Code Scanners** | Anti-Source & Honeypots | Poisons `Function.prototype.toString()` to return `[secure]`, strips Error stacks, deploys bait proxy getters that trigger on AI property scanning. |
| **DevTools Inspection** | Anti-Debug | Staggered timing-based debugger traps + DOM property getter evaluation to detect and halt DevTools inspection. |
| **Token Theft / Memory Dumps** | Secure Storage Enclave | Transparently encrypts `localStorage`/`sessionStorage` with AES-GCM (Web Crypto API) so stored tokens are encrypted ciphertext. |
| **API Tampering & Replay Attacks** | Dynamic Request Signer | Automatically signs outgoing HTTP requests with HMAC-SHA256 nonces and timestamps. Server-side verifier included. |
| **Stealth Bots & Headless Scrapers** | Stealth Bot Detector | Detects Puppeteer-stealth and undetected-chromedriver using GPU software rasterizer checks (SwiftShader/llvmpipe) and screen dimension tests. |
| **Unauthorized Iframe Embedding** | Frame Guard | Validates `document.referrer` against user-configured allowed origins and immediately clears the DOM and redirects. |
| **Runtime Monkey-Patching** | Deep Freeze | Recursively freezes API clients and config objects to block client-side method overrides. |
| **Console Data Harvesting** | Console Silencing | Silences `console.log/info/debug/table/dir/trace` in production builds. |
| **Build-Time Obfuscation** | Bundler Plugin | Vite & Rspack/Webpack plugin to strip console statements and inject runtime preambles automatically. |

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
