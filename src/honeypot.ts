/**
 * @weftcore/aegis - Multi-Scope AI & Scanner Reconnaissance Honeypot Traps
 * 
 * Traps automated scrapers, AI code decompilers, and reverse-engineers inspecting:
 * 1. Global window variables (e.g. apiKey, secretKey, adminToken, __BACKDOOR__)
 * 2. Hidden DOM forms / decoy inputs
 * 3. Synthetic poisoning payloads that return deceptive decoy credentials
 */

export interface HoneypotOptions {
  trapNames?: string[];
  enableDomTraps?: boolean;
  onTrigger?: (trapName: string, detail?: string) => void;
}

const DEFAULT_GLOBAL_TARGETS = [
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
  '__CONFIG_SECRET__',
  'authOverride',
  'rootAccess',
];

export function installHoneypots(options: HoneypotOptions = {}): () => void {
  if (typeof window === 'undefined') return () => {};

  const targets = options.trapNames || DEFAULT_GLOBAL_TARGETS;
  const originalDescriptors = new Map<string, PropertyDescriptor | undefined>();
  const cleanupFns: Array<() => void> = [];

  // 1. Global Window Scanners
  for (const name of targets) {
    if (name in window) continue; // Skip real legitimate globals

    try {
      originalDescriptors.set(name, Object.getOwnPropertyDescriptor(window, name));

      Object.defineProperty(window, name, {
        configurable: true,
        enumerable: false,
        get: () => {
          options.onTrigger?.(name, 'read');
          // Poison the returned payload with synthetic decoy tokens to track unauthorized replay attempts
          return {
            status: 'decoy_active',
            trapId: 'aegis_' + Math.random().toString(36).slice(2),
            token: 'aegis_decoy_' + Date.now().toString(36),
            scope: 'internal_audit_only',
          };
        },
        set: (val) => {
          options.onTrigger?.(name, `write:${typeof val}`);
        },
      });
    } catch {
      /* strict scope */
    }
  }

  cleanupFns.push(() => {
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
  });

  // 2. Hidden Decoy DOM Traps (Traps automated form scrapers & autofillers)
  if (options.enableDomTraps !== false && typeof document !== 'undefined' && document.body) {
    try {
      const trapContainer = document.createElement('div');
      trapContainer.setAttribute('aria-hidden', 'true');
      trapContainer.style.position = 'absolute';
      trapContainer.style.left = '-9999px';
      trapContainer.style.opacity = '0';
      trapContainer.style.pointerEvents = 'none';

      const trapInput = document.createElement('input');
      trapInput.type = 'text';
      trapInput.name = 'admin_override_token';
      trapInput.tabIndex = -1;
      trapInput.autocomplete = 'off';

      trapInput.addEventListener('change', () => {
        options.onTrigger?.('dom-trap:admin_override_token', 'input-modified');
      });

      trapContainer.appendChild(trapInput);
      document.body.appendChild(trapContainer);

      cleanupFns.push(() => trapContainer.remove());
    } catch {
      /* noop */
    }
  }

  return () => {
    cleanupFns.forEach((fn) => fn());
    cleanupFns.length = 0;
  };
}
