/**
 * @weftcore/security
 * Universal client-side runtime security guard.
 * Zero hardcoded domains — fully configurable for any project.
 */
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
export type ViolationType = 'frame-violation' | 'debugger-detected' | 'headless-detected' | 'source-extraction' | 'devtools-shortcut' | 'tampering-detected';
/**
 * Initialize the full security suite. Idempotent — safe to call from multiple entry points.
 */
export declare function initSecurityGuard(options?: SecurityGuardOptions): void;
/**
 * Tear down the guard (useful for testing). Removes all listeners and timers.
 */
export declare function destroySecurityGuard(): void;
export declare function enforceFrameGuard(config: {
    allowedOrigins?: RegExp | string[];
    redirectUrl?: string;
    allowLocalhostInDev?: boolean;
}): void;
export declare function deepFreeze<T extends object>(obj: T): Readonly<T>;
export declare function startAntiDebug(intervalMs?: number): number;
