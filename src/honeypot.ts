/**
 * @weftcore/aegis - AI Reconnaissance Honeypot Traps
 * Sets up trap getters on the global window scope for common target names.
 * When an AI code agent (like REA) or automated scanner interrogates window properties,
 * the honeypot catches the reconnaissance attempt and fires a violation.
 */

export interface HoneypotOptions {
  trapNames?: string[];
  onTrigger?: (trapName: string) => void;
}

const DEFAULT_HONEYPOT_TARGETS = [
  'apiKey',
  'apiSecret',
  'secretKey',
  'adminToken',
  'jwtSecret',
  'userCredentials',
  'superAdmin',
  '__BACKDOOR__',
  'debugAuth',
  'rawToken',
];

export function installHoneypots(options: HoneypotOptions = {}): () => void {
  if (typeof window === 'undefined') return () => {};

  const targets = options.trapNames || DEFAULT_HONEYPOT_TARGETS;
  const originalDescriptors = new Map<string, PropertyDescriptor | undefined>();

  for (const name of targets) {
    if (name in window) continue; // Don't override real existing globals

    try {
      originalDescriptors.set(name, Object.getOwnPropertyDescriptor(window, name));

      Object.defineProperty(window, name, {
        configurable: true,
        enumerable: false,
        get: () => {
          options.onTrigger?.(name);
          // Poison the returned payload so AI agents receive fake decoy credentials
          return {
            status: 'decoy_active',
            trapId: 'aegis_' + Math.random().toString(36).slice(2),
            token: 'aegis_decoy_' + Date.now(),
          };
        },
        set: () => {
          options.onTrigger?.(name + ':write');
        },
      });
    } catch {
      // Ignore if strict environment forbids defining property on window
    }
  }

  // Cleanup function
  return () => {
    for (const [name, desc] of originalDescriptors.entries()) {
      try {
        if (desc) {
          Object.defineProperty(window, name, desc);
        } else {
          delete (window as any)[name];
        }
      } catch {
        /* noop */
      }
    }
  };
}

