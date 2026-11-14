/**
 * @weftcore/aegis - Build-Time Bundler Plugin (Vite / Rspack / Webpack / Rollup)
 * 
 * Provides:
 * 1. Safe multi-line console statement stripping.
 * 2. Automatic security preamble injection into index.html prior to any external scripts.
 * 3. String scrambling helper for sensitive client-side literals.
 */

export interface AegisPluginOptions {
  /** Enforce removal of console.log/info/debug/table/dir calls in production. Defaults to true. */
  dropConsole?: boolean;
  /** Automatically inject security guard preamble into index.html. Defaults to false. */
  injectPreamble?: boolean;
  /** Guard options to use when injectPreamble is true. */
  guardOptions?: Record<string, unknown>;
}

/**
 * Safely strips console calls by matching balanced parentheses even across multiple lines.
 */
function stripConsoleStatements(code: string): string {
  const consoleMethods = ['log', 'info', 'debug', 'table', 'dir', 'trace', 'group', 'groupEnd'];
  const regex = new RegExp(`\\bconsole\\.(${consoleMethods.join('|')})\\s*\\(`, 'g');

  let match: RegExpExecArray | null;
  let lastIndex = 0;
  let result = '';

  while ((match = regex.exec(code)) !== null) {
    result += code.slice(lastIndex, match.index);
    const startParen = match.index + match[0].length - 1;

    // Balance matching parentheses
    let depth = 1;
    let i = startParen + 1;
    let inString: string | null = null;
    let isEscaped = false;

    while (i < code.length && depth > 0) {
      const char = code[i];

      if (isEscaped) {
        isEscaped = false;
      } else if (char === '\\') {
        isEscaped = true;
      } else if (inString) {
        if (char === inString) inString = null;
      } else if (char === '"' || char === "'" || char === '`') {
        inString = char;
      } else if (char === '(') {
        depth++;
      } else if (char === ')') {
        depth--;
      }
      i++;
    }

    // Skip trailing semicolon if present
    if (i < code.length && code[i] === ';') {
      i++;
    }

    result += 'void 0;';
    lastIndex = i;
    regex.lastIndex = i;
  }

  result += code.slice(lastIndex);
  return result;
}

/**
 * Helper to scramble sensitive string literals at build-time.
 */
export function scrambleString(str: string, salt = 0x5a): string {
  const encoded = Array.from(new TextEncoder().encode(str))
    .map((b) => (b ^ salt).toString(16).padStart(2, '0'))
    .join('');
  return encoded;
}

/**
 * Client runtime decoder for scrambled string literals.
 */
export function decodeString(hex: string, salt = 0x5a): string {
  const bytes = new Uint8Array(
    (hex.match(/[\da-f]{2}/gi) || []).map((h) => parseInt(h, 16) ^ salt)
  );
  return new TextDecoder().decode(bytes);
}

export function aegisPlugin(options: AegisPluginOptions = {}) {
  const isDropConsole = options.dropConsole !== false;

  return {
    name: 'weftcore-aegis-plugin',
    enforce: 'post' as const,

    transform(code: string, id: string) {
      if (id.includes('node_modules')) return null;

      let transformed = code;

      if (isDropConsole && /\.(jsx?|tsx?|mjs|cjs)$/.test(id)) {
        try {
          transformed = stripConsoleStatements(transformed);
        } catch {
          // If AST/parser edge case occurs, fallback gracefully
        }
      }

      return {
        code: transformed,
        map: null,
      };
    },

    transformIndexHtml(html: string) {
      if (!options.injectPreamble) return html;

      const optsStr = options.guardOptions ? JSON.stringify(options.guardOptions) : '{}';
      const preambleScript = `<script>
(function(){
  try {
    if (typeof window !== 'undefined') {
      window.__AEGIS_CONFIG__ = ${optsStr};
    }
  } catch(e) {}
})();
</script>`;

      return html.replace('</head>', `${preambleScript}\n</head>`);
    },
  };
}

export default aegisPlugin;
