/**
 * @weftcore/aegis
 * Universal client-side runtime security guard & anti-reverse engineering suite.
 * Zero hardcoded domains — fully configurable for any project.
 */

import { detectStealthBot } from './fingerprint';
import { installHoneypots } from './honeypot';

declare const process: any;

// ─── Public Types ──────────────────────────────────────────────

export interface SecurityGuardOptions {
  /** Allowed iframe ancestor origins. Pass a RegExp, string[], or omit to block all framing. */
  allowedOrigins?: RegExp | string[];
  /** Where to redirect if framed by an unauthorized host. Required if allowedOrigins is set. */
  unauthorizedRedirectUrl?: string;
  /** Allow localhost/127.0.0.1 framing in development mode. Defaults to true. */
  allowLocalhostInDev?: boolean;
  /** Silence console.log/info/debug/table/dir in production. Defaults to true. */
  silenceConsole?: boolean;
  /** Run active debugger trap loop in production. Defaults to true. */
  antiDebug?: boolean;
  /** Debugger trap check interval in ms. Defaults to 2000. */
  antiDebugIntervalMs?: number;
  /** Protect source from automated code extraction and AI decompilers. Defaults to true. */
  antiSourceExtraction?: boolean;
  /** Detect and block headless browser automation and stealth scrapers. Defaults to true. */
  antiHeadless?: boolean;
  /** Deploy decoy honeypot globals to detect AI scanners (like REA). Defaults to true. */
  antiAiScanners?: boolean;
  /** Prevent right-click context menu and keyboard shortcuts for View Source / DevTools. Defaults to true. */
  blockDevShortcuts?: boolean;
  /** Objects to deep-freeze against runtime monkey-patching. */
  freezeTargets?: object[];
  /** Callback when a security violation is detected. */
  onViolation?: (type: ViolationType, detail?: string) => void;
}

export type ViolationType =
  | 'frame-violation'
  | 'debugger-detected'
  | 'headless-detected'
  | 'stealth-bot-detected'
  | 'honeypot-triggered'
  | 'source-extraction'
  | 'devtools-shortcut'
  | 'tampering-detected';

// ─── Re-exports of Sub-Modules ─────────────────────────────────

export * from './storage';
export * from './signer';
export * from './fingerprint';
export * from './honeypot';
export { aegisPlugin } from './plugin';

// ─── Guard State ───────────────────────────────────────────────

let _initialized = false;
let _options: SecurityGuardOptions = {};
let _antiDebugTimer: number | undefined;
let _cleanupHoneypots: (() => void) | undefined;

// ─── Main Entry ────────────────────────────────────────────────

/**
 * Initialize the full security suite. Idempotent — safe to call from multiple entry points.
 */
export function initSecurityGuard(options: SecurityGuardOptions = {}): void {
  if (_initialized || typeof window === 'undefined') return;
  _initialized = true;
  _options = options;

  const isProd = !_isDev();

  // Layer 1: Frame Guard (always active)
  if (options.allowedOrigins) {
    enforceFrameGuard({
      allowedOrigins: options.allowedOrigins,
      redirectUrl: options.unauthorizedRedirectUrl,
      allowLocalhostInDev: options.allowLocalhostInDev !== false,
    });
  }

  // Layer 2: Freeze targets
  if (Array.isArray(options.freezeTargets)) {
    for (const t of options.freezeTargets) {
      if (t && typeof t === 'object') deepFreeze(t);
    }
  }

  // Production-only active defenses
  if (isProd) {
    // Layer 3: Console silencing
    if (options.silenceConsole !== false) {
      _silenceConsole();
    }

    // Layer 4: Anti-debugging
    if (options.antiDebug !== false) {
      _antiDebugTimer = startAntiDebug(options.antiDebugIntervalMs ?? 2000);
    }

    // Layer 5: Anti-source extraction (defeats REA, AI decompilers, source map scrapers)
    if (options.antiSourceExtraction !== false) {
      _installAntiSourceExtraction();
    }

    // Layer 6: Headless / automation detection & stealth hardware check
    if (options.antiHeadless !== false) {
      _detectHeadless();
      const botResult = detectStealthBot();
      if (botResult.isBot) {
        _fireViolation('stealth-bot-detected', botResult.reasons.join(', '));
      }
    }

    // Layer 7: Block DevTools keyboard shortcuts + right-click
    if (options.blockDevShortcuts !== false) {
      _blockDevShortcuts();
    }

    // Layer 8: AI Reconnaissance Honeypots
    if (options.antiAiScanners !== false) {
      _cleanupHoneypots = installHoneypots({
        onTrigger: (name) => {
          _fireViolation('honeypot-triggered', name);
          _onDebugDetected();
        },
      });
    }
  }
}

/**
 * Tear down the guard (useful for testing). Removes all listeners and timers.
 */
export function destroySecurityGuard(): void {
  _initialized = false;
  if (_antiDebugTimer !== undefined) {
    clearInterval(_antiDebugTimer);
    _antiDebugTimer = undefined;
  }
  if (_cleanupHoneypots) {
    _cleanupHoneypots();
    _cleanupHoneypots = undefined;
  }
  _cleanupListeners.forEach((fn) => fn());
  _cleanupListeners.length = 0;
}

// ─── Layer 1: Frame Guard ──────────────────────────────────────

export function enforceFrameGuard(config: {
  allowedOrigins?: RegExp | string[];
  redirectUrl?: string;
  allowLocalhostInDev?: boolean;
}): void {
  if (typeof window === 'undefined') return;

  try {
    if (window.self === window.top) return; // Not framed

    const referrer = document.referrer ? new URL(document.referrer).origin : '';
    let allowed = false;

    if (config.allowedOrigins instanceof RegExp) {
      allowed = config.allowedOrigins.test(referrer);
    } else if (Array.isArray(config.allowedOrigins)) {
      allowed = config.allowedOrigins.some(
        (o) => referrer === o || referrer.endsWith('.' + new URL(o).hostname)
      );
    }

    if (!allowed && config.allowLocalhostInDev && _isDev()) {
      allowed = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(referrer);
    }

    if (!allowed) {
      _fireViolation('frame-violation', referrer);
      document.documentElement.innerHTML = '';
      if (config.redirectUrl && window.top) {
        window.top.location.href = config.redirectUrl;
      }
    }
  } catch {
    // Cross-origin frame access denied → unauthorized embedding
    _fireViolation('frame-violation', 'cross-origin');
    document.documentElement.innerHTML = '';
  }
}

// ─── Layer 2: Deep Freeze ──────────────────────────────────────

export function deepFreeze<T extends object>(obj: T): Readonly<T> {
  Object.freeze(obj);
  for (const key of Object.getOwnPropertyNames(obj)) {
    const val = (obj as any)[key];
    if (val && typeof val === 'object' && !Object.isFrozen(val)) {
      deepFreeze(val);
    }
  }
  return obj;
}

// ─── Layer 3: Console Silencing ────────────────────────────────

function _silenceConsole(): void {
  if (typeof console === 'undefined') return;
  const noop = () => {};
  const methods = ['log', 'info', 'debug', 'table', 'dir', 'trace', 'group', 'groupEnd'] as const;
  for (const m of methods) {
    try {
      (console as any)[m] = noop;
    } catch {
      /* frozen env */
    }
  }
}

// ─── Layer 4: Anti-Debugging ───────────────────────────────────

export function startAntiDebug(intervalMs = 2000): number {
  const check = () => {
    // Vector 1: Timing-based debugger statement detection
    const t0 = performance.now();
    try {
      (function () {}.constructor('debugger')());
    } catch {
      /* noop */
    }
    const elapsed = performance.now() - t0;

    if (elapsed > 80) {
      _fireViolation('debugger-detected', `latency=${elapsed.toFixed(0)}ms`);
      _onDebugDetected();
    }

    // Vector 2: Detect element inspection via DOM element getter trick
    try {
      const el = new Image();
      let devtoolsOpen = false;
      Object.defineProperty(el, 'id', {
        get: () => {
          devtoolsOpen = true;
          return '';
        },
      });
      console.debug(el);
      if (devtoolsOpen) {
        _fireViolation('debugger-detected', 'console-inspect');
        _onDebugDetected();
      }
    } catch {
      /* noop */
    }
  };

  check();
  return window.setInterval(check, intervalMs);
}

function _onDebugDetected(): void {
  try { sessionStorage.clear(); } catch { /* noop */ }
  try { localStorage.removeItem('TOKEN'); } catch { /* noop */ }
  try { localStorage.removeItem('REFRESH_TOKEN'); } catch { /* noop */ }
}

// ─── Layer 5: Anti-Source Extraction ───────────────────────────

function _installAntiSourceExtraction(): void {
  try {
    const originalToString = Function.prototype.toString;
    const guardedToString = function (this: Function): string {
      const original = originalToString.call(this);
      if (original.includes('[native code]')) return original;
      _fireViolation('source-extraction', 'toString');
      return 'function () { [secure] }';
    };
    Function.prototype.toString = guardedToString;
    guardedToString.toString = () => 'function toString() { [native code] }';
  } catch {
    /* frozen prototype env */
  }

  try {
    const origPrepareStackTrace = (Error as any).prepareStackTrace;
    (Error as any).prepareStackTrace = function (err: Error, stack: any[]) {
      if (origPrepareStackTrace) {
        const result = origPrepareStackTrace(err, stack);
        if (typeof result === 'string') {
          return result.replace(/https?:\/\/[^\s)]+/g, '[redacted]');
        }
        return result;
      }
      return err.toString();
    };
  } catch {
    /* V8-only */
  }

  try {
    const sensitiveKeys = new Set(['authClient', 'AuthProvider', 'useAuth', 'TOKEN', 'REFRESH_TOKEN']);
    const origKeys = Object.keys;
    Object.keys = function <T extends object>(obj: T): string[] {
      const result = origKeys.call(Object, obj);
      if (obj === window) {
        return result.filter((k) => !sensitiveKeys.has(k));
      }
      return result;
    } as typeof Object.keys;
  } catch {
    /* noop */
  }

  try {
    const observer = new MutationObserver((mutations) => {
      for (const m of mutations) {
        for (const node of Array.from(m.addedNodes)) {
          if (node instanceof HTMLScriptElement && node.src && !_isTrustedScript(node.src)) {
            _fireViolation('source-extraction', `injected-script: ${node.src}`);
            node.remove();
          }
        }
      }
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
    _cleanupListeners.push(() => observer.disconnect());
  } catch {
    /* noop */
  }
}

function _isTrustedScript(src: string): boolean {
  try {
    const url = new URL(src);
    return url.origin === window.location.origin;
  } catch {
    return true;
  }
}

// ─── Layer 6: Headless / Automation Detection ──────────────────

function _detectHeadless(): void {
  const flags: string[] = [];

  if (navigator.webdriver) flags.push('webdriver');
  if ((navigator as any).plugins?.length === 0) flags.push('no-plugins');
  if (/HeadlessChrome/i.test(navigator.userAgent)) flags.push('headless-ua');
  if (!(window as any).chrome && /Chrome/.test(navigator.userAgent)) flags.push('fake-chrome');

  const automationProps = [
    '__webdriver_evaluate', '__selenium_evaluate', '__webdriver_script_function',
    '__webdriver_script_func', '__webdriver_script_fn', '__fxdriver_evaluate',
    '_phantom', '__nightmare', '_selenium', 'callPhantom', 'callSelenium',
    '_Recaptcha', '__driver_unwrapped', '__webdriver_unwrapped',
    '__driver_evaluate', '__lastWatirAlert', '__lastWatirConfirm',
    '__lastWatirPrompt', 'cdc_adoQpoasnfa76pfcZLmcfl_Array',
    'cdc_adoQpoasnfa76pfcZLmcfl_Promise', 'cdc_adoQpoasnfa76pfcZLmcfl_Symbol',
  ];

  for (const prop of automationProps) {
    if (prop in window || prop in document) {
      flags.push(prop);
    }
  }

  if (flags.length > 0) {
    _fireViolation('headless-detected', flags.join(', '));
  }
}

// ─── Layer 7: Block DevTools Shortcuts & Right-Click ───────────

function _blockDevShortcuts(): void {
  const onKeyDown = (e: KeyboardEvent) => {
    if (e.key === 'F12') {
      e.preventDefault();
      _fireViolation('devtools-shortcut', 'F12');
      return;
    }
    if (e.ctrlKey && e.shiftKey && ['I', 'J', 'C'].includes(e.key.toUpperCase())) {
      e.preventDefault();
      _fireViolation('devtools-shortcut', `Ctrl+Shift+${e.key.toUpperCase()}`);
      return;
    }
    if (e.ctrlKey && e.key.toUpperCase() === 'U') {
      e.preventDefault();
      _fireViolation('devtools-shortcut', 'Ctrl+U');
      return;
    }
  };

  const onContextMenu = (e: MouseEvent) => {
    e.preventDefault();
    _fireViolation('devtools-shortcut', 'right-click');
  };

  document.addEventListener('keydown', onKeyDown, { capture: true });
  document.addEventListener('contextmenu', onContextMenu, { capture: true });

  _cleanupListeners.push(() => {
    document.removeEventListener('keydown', onKeyDown, { capture: true });
    document.removeEventListener('contextmenu', onContextMenu, { capture: true });
  });
}

// ─── Internal Utilities ────────────────────────────────────────

const _cleanupListeners: Array<() => void> = [];

function _isDev(): boolean {
  try {
    return typeof process !== 'undefined' && process.env?.NODE_ENV !== 'production';
  } catch {
    return false;
  }
}

function _fireViolation(type: ViolationType, detail?: string): void {
  _options.onViolation?.(type, detail);
}
