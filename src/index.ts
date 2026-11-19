/**
 * @weftcore/aegis
 * Universal client-side runtime security guard & anti-reverse engineering suite.
 * Zero hardcoded domains — fully configurable for any project.
 */

import { detectStealthBot, type BotDetectionResult } from './fingerprint';
import { installHoneypots } from './honeypot';

declare const process: any;

// ─── Public Types ──────────────────────────────────────────────

export interface SecurityGuardOptions {
  /** Allowed iframe ancestor origins. Pass a RegExp, string[], or omit to block all framing. */
  allowedOrigins?: RegExp | string[];
  /** Where to redirect if framed by an unauthorized host or upon severe security breach. */
  unauthorizedRedirectUrl?: string;
  /** Allow localhost/127.0.0.1 framing in development mode. Defaults to true. */
  allowLocalhostInDev?: boolean;
  /** Allow opening DevTools without triggering anti-debug traps, dimension checks, or shortcut blocks. Defaults to true on localhost/dev. */
  allowDevToolOpen?: boolean;
  /** Silence console.log/info/debug/table/dir in production. Defaults to true. */
  silenceConsole?: boolean;
  /** Run active multi-vector debugger and DevTools detection in production. Defaults to true. */
  antiDebug?: boolean;
  /** Check interval in ms for DevTools detection. Defaults to 1500. */
  antiDebugIntervalMs?: number;
  /** Enable docked DevTools dimension differential detection. Defaults to true. */
  detectDevToolsDimensions?: boolean;
  /** Enable background Web Worker heartbeat debugger trap. Defaults to true. */
  enableWorkerHeartbeat?: boolean;
  /** Protect prototypes from clean iframe extraction and unauthorized script injection. Defaults to true. */
  antiSourceExtraction?: boolean;
  /** Detect and flag headless browser automation, Puppeteer, and Selenium. Defaults to true. */
  antiHeadless?: boolean;
  /** Deploy synthetic AI reconnaissance honeypots. Defaults to true. */
  antiAiScanners?: boolean;
  /** Prevent right-click context menu and keyboard shortcuts for DevTools. Defaults to true. */
  blockDevShortcuts?: boolean;
  /** Objects to deep-freeze against runtime monkey-patching. */
  freezeTargets?: object[];
  /** Callback when a security violation is detected. */
  onViolation?: (type: ViolationType, detail?: string) => void;
}

export type ViolationType =
  | 'frame-violation'
  | 'debugger-detected'
  | 'devtools-opened'
  | 'headless-detected'
  | 'stealth-bot-detected'
  | 'honeypot-triggered'
  | 'source-extraction'
  | 'devtools-shortcut'
  | 'prototype-tampering'
  | 'tampering-detected';

// ─── Re-exports of Sub-Modules ─────────────────────────────────

export * from './storage';
export * from './signer';
export * from './fingerprint';
export * from './honeypot';
export { aegisPlugin, scrambleString, decodeString } from './plugin';

// ─── Guard State ───────────────────────────────────────────────

let _initialized = false;
let _options: SecurityGuardOptions = {};
let _antiDebugTimer: number | undefined;
let _cleanupHoneypots: (() => void) | undefined;
let _workerHeartbeat: Worker | undefined;
const _cleanupListeners: Array<() => void> = [];

// ─── Main Entry ────────────────────────────────────────────────

/**
 * Initialize the full security suite. Idempotent — safe to call from multiple entry points.
 */
export function initSecurityGuard(options: SecurityGuardOptions = {}): void {
  if (_initialized || typeof window === 'undefined') return;
  _initialized = true;
  _options = options;

  const isDev = _isDev();
  const allowDevTools = options.allowDevToolOpen ?? isDev;

  // Layer 1: Frame Guard (active in all modes)
  if (options.allowedOrigins) {
    enforceFrameGuard({
      allowedOrigins: options.allowedOrigins,
      redirectUrl: options.unauthorizedRedirectUrl,
      allowLocalhostInDev: options.allowLocalhostInDev !== false,
    });
  }

  // Layer 2: Deep Freeze targets
  if (Array.isArray(options.freezeTargets)) {
    for (const t of options.freezeTargets) {
      if (t && typeof t === 'object') deepFreeze(t);
    }
  }

  // Anti-debugging, console silencing, & shortcuts: active ONLY when DevTools is NOT allowed
  if (!allowDevTools) {
    // Layer 3: Console silencing
    if (options.silenceConsole !== false) {
      _silenceConsole();
    }

    // Layer 4: Anti-debugging & DevTools dimension detection
    if (options.antiDebug !== false) {
      _antiDebugTimer = startAntiDebug({
        intervalMs: options.antiDebugIntervalMs ?? 1500,
        detectDimensions: options.detectDevToolsDimensions !== false,
        enableWorker: options.enableWorkerHeartbeat !== false,
      });
    }

    // Layer 5: Block DevTools shortcuts and right-click
    if (options.blockDevShortcuts !== false) {
      _blockDevShortcuts();
    }
  }

  // Production-only tamper & bot protections
  if (!isDev) {
    // Layer 6: Prototype sealing & clean-iframe extraction prevention
    if (options.antiSourceExtraction !== false) {
      _installAntiSourceExtraction();
    }

    // Layer 7: Headless / automation detection & hardware evaluation
    if (options.antiHeadless !== false) {
      _detectHeadless();
      const botResult: BotDetectionResult = detectStealthBot();
      if (botResult.isBot) {
        _fireViolation('stealth-bot-detected', botResult.reasons.join(', '));
      }
    }

    // Layer 8: AI Reconnaissance Honeypots
    if (options.antiAiScanners !== false) {
      _cleanupHoneypots = installHoneypots({
        onTrigger: (name, detail) => {
          _fireViolation('honeypot-triggered', `${name}:${detail || ''}`);
        },
      });
    }
  }
}

/**
 * Tear down the guard (useful for tests). Removes all listeners and timers.
 */
export function destroySecurityGuard(): void {
  _initialized = false;
  if (_antiDebugTimer !== undefined) {
    clearInterval(_antiDebugTimer);
    _antiDebugTimer = undefined;
  }
  if (_workerHeartbeat) {
    _workerHeartbeat.terminate();
    _workerHeartbeat = undefined;
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
    if (window.self === window.top) return; // Not embedded in an iframe

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
      _fireViolation('frame-violation', referrer || 'unknown-origin');
      document.documentElement.innerHTML = '';
      if (config.redirectUrl && window.top) {
        window.top.location.href = config.redirectUrl;
      }
    }
  } catch {
    _fireViolation('frame-violation', 'cross-origin-blocked');
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
      /* frozen environment */
    }
  }
}

// ─── Layer 4: Anti-Debugging & DevTools Detection ──────────────

export interface AntiDebugOptions {
  intervalMs?: number;
  detectDimensions?: boolean;
  enableWorker?: boolean;
}

export function startAntiDebug(options: AntiDebugOptions | number = 1500): number {
  const opts: AntiDebugOptions = typeof options === 'number' ? { intervalMs: options } : options;
  const intervalMs = opts.intervalMs ?? 1500;

  // 1. Web Worker Heartbeat (Off-thread detection)
  if (opts.enableWorker !== false && typeof Worker !== 'undefined' && typeof Blob !== 'undefined') {
    try {
      const workerBlob = new Blob(
        [
          `let lastHeartbeat = Date.now();
           self.onmessage = function(e) {
             if (e.data === 'pong') lastHeartbeat = Date.now();
           };
           setInterval(function() {
             self.postMessage('ping');
             if (Date.now() - lastHeartbeat > 3500) {
               self.postMessage('detected');
             }
           }, 1000);`,
        ],
        { type: 'application/javascript' }
      );
      const workerUrl = URL.createObjectURL(workerBlob);
      _workerHeartbeat = new Worker(workerUrl);
      _workerHeartbeat.onmessage = (e) => {
        if (e.data === 'ping') {
          _workerHeartbeat?.postMessage('pong');
        } else if (e.data === 'detected') {
          _fireViolation('debugger-detected', 'worker-heartbeat-stalled');
        }
      };
      _cleanupListeners.push(() => {
        _workerHeartbeat?.terminate();
        URL.revokeObjectURL(workerUrl);
      });
    } catch {
      /* Worker disabled by CSP */
    }
  }

  const check = () => {
    // 2. Docked DevTools Dimension Differential Check (Gold Standard)
    if (opts.detectDimensions !== false && typeof window !== 'undefined') {
      const widthDiff = window.outerWidth - window.innerWidth;
      const heightDiff = window.outerHeight - window.innerHeight;
      // When DevTools is docked to side or bottom, threshold typically exceeds 160px
      if (widthDiff > 160 || heightDiff > 160) {
        _fireViolation('devtools-opened', `docked: wDiff=${widthDiff}, hDiff=${heightDiff}`);
      }
    }

    // 3. Timing-Based Debugger Trap
    const t0 = performance.now();
    try {
      (function () {}.constructor('debugger')());
    } catch {
      /* noop */
    }
    const elapsed = performance.now() - t0;

    if (elapsed > 80) {
      _fireViolation('debugger-detected', `debugger-latency=${elapsed.toFixed(0)}ms`);
    }
  };

  check();
  return window.setInterval(check, intervalMs);
}

// ─── Layer 5: Prototype Sealing & Anti-Source Extraction ───────

function _installAntiSourceExtraction(): void {
  // 1. Protect Function.prototype.toString
  try {
    const originalToString = Function.prototype.toString;
    const guardedToString = function (this: Function): string {
      const original = originalToString.call(this);
      if (original.includes('[native code]')) return original;
      return 'function () { [native code] }';
    };
    Function.prototype.toString = guardedToString;
    guardedToString.toString = () => 'function toString() { [native code] }';
  } catch {
    /* frozen prototype */
  }

  // 2. Protect Error.prepareStackTrace from leaking internal bundle paths
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
    /* V8 only */
  }

  // 3. Iframe Sandbox Prototype Guard
  // Prevents attackers from creating a hidden iframe to extract clean un-guarded prototypes!
  try {
    const origCreateElement = document.createElement.bind(document);
    document.createElement = function (tagName: string, options?: ElementCreationOptions): any {
      const element = origCreateElement(tagName, options);
      if (typeof tagName === 'string' && tagName.toLowerCase() === 'iframe') {
        element.addEventListener('load', () => {
          try {
            const iframeWin = (element as HTMLIFrameElement).contentWindow as any;
            if (iframeWin && iframeWin.Function) {
              iframeWin.Function.prototype.toString = Function.prototype.toString;
            }
          } catch {
            /* Cross-origin iframe */
          }
        });
      }
      return element;
    } as any;
  } catch {
    /* noop */
  }

  // 4. MutationObserver to block unauthorized external script injections
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
    if (prop in window || (document && prop in document)) {
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
    // F12
    if (e.key === 'F12') {
      e.preventDefault();
      _fireViolation('devtools-shortcut', 'F12');
      return;
    }
    // Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+Shift+C (or Cmd+Option on Mac)
    if ((e.ctrlKey || e.metaKey) && (e.shiftKey || e.altKey) && ['I', 'J', 'C'].includes(e.key.toUpperCase())) {
      e.preventDefault();
      _fireViolation('devtools-shortcut', `DevTools-${e.key.toUpperCase()}`);
      return;
    }
    // Ctrl+U / Cmd+U (View Source)
    if ((e.ctrlKey || e.metaKey) && e.key.toUpperCase() === 'U') {
      e.preventDefault();
      _fireViolation('devtools-shortcut', 'ViewSource');
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

function _isDev(): boolean {
  try {
    if (typeof window !== 'undefined' && window.location) {
      const host = window.location.hostname;
      if (host === 'localhost' || host === '127.0.0.1' || host.endsWith('.local')) {
        return true;
      }
    }
    return typeof process !== 'undefined' && process.env?.NODE_ENV !== 'production';
  } catch {
    return false;
  }
}

function _fireViolation(type: ViolationType, detail?: string): void {
  _options.onViolation?.(type, detail);
}
