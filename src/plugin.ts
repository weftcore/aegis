/**
 * @weftcore/aegis - Build-Time Bundler Plugin (Vite / Rspack / Webpack)
 * Automates string scrambling, header injection, and security preambles during build time.
 */

export interface AegisPluginOptions {
  /** Enforce removal of console.log/info/debug calls in production. Defaults to true. */
  dropConsole?: boolean;
  /** Automatically inject security guard preamble into index.html. Defaults to false. */
  injectPreamble?: boolean;
  /** Guard options to use when injectPreamble is true. */
  guardOptions?: Record<string, unknown>;
}

export function aegisPlugin(options: AegisPluginOptions = {}) {
  const isDropConsole = options.dropConsole !== false;

  return {
    name: 'weftcore-aegis-plugin',
    enforce: 'post' as const,

    // Vite / Rollup / Rspack transform hook
    transform(code: string, id: string) {
      // Ignore node_modules
      if (id.includes('node_modules')) return null;

      let transformed = code;

      // 1. Strip console statements in production if enabled
      if (isDropConsole && /\.(jsx?|tsx?)$/.test(id)) {
        transformed = transformed.replace(
          /\bconsole\.(log|info|debug|table|dir)\s*\([^)]*\);?/g,
          '/* [aegis-stripped] */'
        );
      }

      return {
        code: transformed,
        map: null,
      };
    },

    // HTML transformation hook (for Vite / Rspack HtmlPlugin)
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

