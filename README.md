# @weftcore/aegis

🛡️ Universal client-side runtime security guard and anti-reverse-engineering suite.

Zero hardcoded domains. Zero dependencies. Works with **any** web app, on **any** domain.

## Install

```bash
npm install @weftcore/aegis
```

## Quick Start

```typescript
import { initSecurityGuard } from '@weftcore/aegis';

initSecurityGuard({
  allowedOrigins: ['https://example.com', 'https://app.example.com'],
  unauthorizedRedirectUrl: 'https://example.com',
});
```

Or with a regex pattern:

```typescript
initSecurityGuard({
  allowedOrigins: /^https:\/\/([a-zA-Z0-9-]+\.)?example\.com$/,
  unauthorizedRedirectUrl: 'https://example.com',
});
```

## What It Protects Against

| Threat | Layer | Defense |
|---|---|---|
| **REA / AI decompilers** | Anti-Source Extraction | Poisons `Function.prototype.toString()`, strips Error stacks, hides globals from `Object.keys(window)` |
| **Headless scraping** (Puppeteer, Playwright, Selenium) | Anti-Headless | Detects `navigator.webdriver`, 70+ automation markers, UA fingerprints, permission inconsistencies |
| **Chrome DevTools inspection** | Anti-Debug | Timing-based `debugger` traps, DOM element getter detection, session wipe on breach |
| **View Source / right-click** | Block DevTools Shortcuts | Intercepts F12, Ctrl+Shift+I/J/C, Ctrl+U, right-click context menu |
| **Unauthorized iframe embedding** | Frame Guard | Validates `document.referrer` against your allowed origins, breaks out of rogue frames |
| **Runtime monkey-patching** | Deep Freeze | Recursively freezes API clients & config objects, preventing `.fetch` / `.login` overrides |
| **Console data harvesting** | Console Silencing | Replaces `console.log/info/debug/table/dir/trace/group` with no-ops in production |

## API

### `initSecurityGuard(options?)`

All options are optional. Defaults activate all production defenses.

| Option | Type | Default | Description |
|---|---|---|---|
| `allowedOrigins` | `RegExp \| string[]` | — | Allowed iframe ancestor origins |
| `unauthorizedRedirectUrl` | `string` | — | Redirect URL for unauthorized frames |
| `allowLocalhostInDev` | `boolean` | `true` | Allow localhost framing in dev |
| `silenceConsole` | `boolean` | `true` | Silence console methods in production |
| `antiDebug` | `boolean` | `true` | Run debugger trap loop in production |
| `antiDebugIntervalMs` | `number` | `2000` | Debugger check interval |
| `antiSourceExtraction` | `boolean` | `true` | Protect from REA / AI source extraction |
| `antiHeadless` | `boolean` | `true` | Detect headless browser automation |
| `blockDevShortcuts` | `boolean` | `true` | Block F12 / Ctrl+Shift+I / right-click |
| `freezeTargets` | `object[]` | — | Objects to deep-freeze |
| `onViolation` | `(type, detail?) => void` | — | Callback on security violations |

### Violation Types

```typescript
type ViolationType =
  | 'frame-violation'
  | 'debugger-detected'
  | 'headless-detected'
  | 'source-extraction'
  | 'devtools-shortcut'
  | 'tampering-detected';
```

### Exported Utilities

```typescript
import {
  initSecurityGuard,
  destroySecurityGuard,
  enforceFrameGuard,
  startAntiDebug,
  deepFreeze,
} from '@weftcore/aegis';
```

## Advanced Usage

```typescript
import { initSecurityGuard } from '@weftcore/aegis';
import { apiClient } from './services/api';
import { config } from './config';

initSecurityGuard({
  allowedOrigins: /^https:\/\/([a-zA-Z0-9-]+\.)?yourdomain\.com$/,
  unauthorizedRedirectUrl: 'https://yourdomain.com',
  freezeTargets: [apiClient, config],
  onViolation: (type, detail) => {
    fetch('/api/security-log', {
      method: 'POST',
      body: JSON.stringify({ type, detail, timestamp: Date.now() }),
    }).catch(() => {});
  },
});
```

## License

MIT © [weftcore](https://github.com/weftcore)

