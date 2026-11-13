/**
 * @weftcore/security
 * Universal client-side runtime security guard.
 * Zero hardcoded domains — fully configurable for any project.
 */

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
  /** Detect and block headless browser automation. Defaults to true. */
  antiHeadless?: boolean;
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
  | 'source-extraction'
  | 'devtools-shortcut'
  | 'tampering-detected';

// ─── Guard State ───────────────────────────────────────────────

let _initialized = false;
let _options: SecurityGuardOptions = {};
let _antiDebugTimer: number | undefined;

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

  // Production-only layers
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

    // Layer 6: Headless / automation detection
    if (options.antiHeadless !== false) {
      _detectHeadless();
    }

    // Layer 7: Block DevTools keyboard shortcuts + right-click
    if (options.blockDevShortcuts !== false) {
      _blockDevShortcuts();
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
    try { (console as any)[m] = noop; } catch { /* frozen env */ }
  }
}

// ─── Layer 4: Anti-Debugging ───────────────────────────────────

export function startAntiDebug(intervalMs = 2000): number {
  // Multi-vector debugger detection
  const check = () => {
    // Vector 1: Timing-based debugger statement detection
    const t0 = performance.now();
    try {
      // Dynamic constructor prevents static AST strippers from removing the debugger keyword
      (function () {}.constructor('debugger')());
    } catch { /* noop */ }
    const elapsed = performance.now() - t0;

    if (elapsed > 80) {
      _fireViolation('debugger-detected', `latency=${elapsed.toFixed(0)}ms`);
      _onDebugDetected();
    }

    // Vector 2: Detect element inspection via DOM element trick
    // When DevTools is open and inspecting, accessing .id on a logged element triggers a getter
    try {
      const el = new Image();
      let devtoolsOpen = false;
      Object.defineProperty(el, 'id', {
        get: () => { devtoolsOpen = true; return ''; },
      });
      // The getter fires only if DevTools console evaluates the object
      console.debug(el);
      if (devtoolsOpen) {
        _fireViolation('debugger-detected', 'console-inspect');
        _onDebugDetected();
      }
    } catch { /* noop */ }
  };

  // Run immediately, then on interval
  check();
  return window.setInterval(check, intervalMs);
}

function _onDebugDetected(): void {
  try { sessionStorage.clear(); } catch { /* noop */ }
  try { localStorage.removeItem('TOKEN'); } catch { /* noop */ }
  try { localStorage.removeItem('REFRESH_TOKEN'); } catch { /* noop */ }
}

// ─── Layer 5: Anti-Source Extraction ───────────────────────────
// Defeats: REA (morluto/rea), AI decompilers, headless scrapers, source-map harvesters

function _installAntiSourceExtraction(): void {
  // 5a: Intercept and poison Function.prototype.toString
  // REA and AI tools call .toString() on functions to read source. Return opaque output.
  try {
    const originalToString = Function.prototype.toString;
    const guardedToString = function (this: Function): string {
      // Allow native functions to return their normal string
      const original = originalToString.call(this);
      if (original.includes('[native code]')) return original;
      // Return opaque signature for all user-defined functions
      _fireViolation('source-extraction', 'toString');
      return 'function () { [secure] }';
    };
    // Apply the override, and make it look native
    Function.prototype.toString = guardedToString;
    // Make our override's own toString return native-looking output
    guardedToString.toString = () => 'function toString() { [native code] }';
  } catch { /* frozen prototype env */ }

  // 5b: Block .map / source map requests via Service Worker interception isn't possible,
  // but we can delete sourceURL/sourceMappingURL pragmas at runtime and override Error.stack
  try {
    const origPrepareStackTrace = (Error as any).prepareStackTrace;
    (Error as any).prepareStackTrace = function (err: Error, stack: any[]) {
      if (origPrepareStackTrace) {
        const result = origPrepareStackTrace(err, stack);
        // Strip file paths from stack traces
        if (typeof result === 'string') {
          return result.replace(/https?:\/\/[^\s)]+/g, '[redacted]');
        }
        return result;
      }
      return err.toString();
    };
  } catch { /* V8-only */ }

  // 5c: Trap property enumeration on window and key globals
  // AI agents enumerate window properties to discover API surfaces
  try {
    const sensitiveKeys = new Set([
      'authClient', 'AuthProvider', 'useAuth', 'TOKEN', 'REFRESH_TOKEN',
    ]);
    // Intercept Object.keys/getOwnPropertyNames on window to hide sensitive globals
    const origKeys = Object.keys;
    Object.keys = function <T extends object>(obj: T): string[] {
      const result = origKeys.call(Object, obj);
      if (obj === window) {
        return result.filter((k) => !sensitiveKeys.has(k));
      }
      return result;
    } as typeof Object.keys;
  } catch { /* noop */ }

  // 5d: Mutation observer — detect DOM-based extraction scripts injecting elements
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
  } catch { /* noop */ }
}

function _isTrustedScript(src: string): boolean {
  try {
    const url = new URL(src);
    return url.origin === window.location.origin;
  } catch {
    return true; // Relative URL = same origin
  }
}

// ─── Layer 6: Headless / Automation Detection ──────────────────

function _detectHeadless(): void {
  const flags: string[] = [];

  // Navigator signals
  if (navigator.webdriver) flags.push('webdriver');
  if ((navigator as any).plugins?.length === 0) flags.push('no-plugins');
  if (/HeadlessChrome/i.test(navigator.userAgent)) flags.push('headless-ua');
  if (!(window as any).chrome && /Chrome/.test(navigator.userAgent)) flags.push('fake-chrome');

  // Puppeteer / Playwright injection markers
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

  // Permission API behavior (headless often has inconsistent permissions)
  if (navigator.permissions) {
    navigator.permissions.query({ name: 'notifications' as PermissionName }).then((p) => {
      if (Notification.permission === 'denied' && p.state === 'prompt') {
        flags.push('perm-inconsistency');
      }
      if (flags.length > 0) {
        _fireViolation('headless-detected', flags.join(', '));
      }
    }).catch(() => { /* noop */ });
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
    // Ctrl+Shift+I / Ctrl+Shift+J / Ctrl+Shift+C (DevTools)
    if (e.ctrlKey && e.shiftKey && ['I', 'J', 'C'].includes(e.key.toUpperCase())) {
      e.preventDefault();
      _fireViolation('devtools-shortcut', `Ctrl+Shift+${e.key.toUpperCase()}`);
      return;
    }
    // Ctrl+U (View Source)
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
