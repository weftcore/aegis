/**
 * @weftcore/aegis - Stealth Headless & Bot Detection (Hardware Fingerprint)
 * Detects advanced stealth scrapers (puppeteer-extra-plugin-stealth, undetected-chromedriver)
 * by evaluating hardware characteristics that headless engines cannot cleanly spoof.
 */

export interface BotDetectionResult {
  isBot: boolean;
  score: number; // 0 (human) to 100 (confirmed bot)
  reasons: string[];
}

export function detectStealthBot(): BotDetectionResult {
  if (typeof window === 'undefined') {
    return { isBot: false, score: 0, reasons: [] };
  }

  const reasons: string[] = [];
  let score = 0;

  // 1. WebGL Software Renderer Check (Headless clouds typically run software rasterizers)
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (gl) {
      const debugInfo = (gl as WebGLRenderingContext).getExtension('WEBGL_debug_renderer_info');
      if (debugInfo) {
        const renderer = (gl as WebGLRenderingContext).getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || '';
        const vendor = (gl as WebGLRenderingContext).getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || '';

        // Known virtualized/software GPU signatures
        const virtualGpus = ['SwiftShader', 'llvmpipe', 'VirtualBox', 'VMware', 'Mesa OffScreen', 'Microsoft Basic Render'];
        for (const gpu of virtualGpus) {
          if (renderer.includes(gpu) || vendor.includes(gpu)) {
            score += 45;
            reasons.push(`software-gpu: ${gpu}`);
            break;
          }
        }
      }
    } else {
      score += 20;
      reasons.push('no-webgl');
    }
  } catch {
    /* noop */
  }

  // 2. Hardware Concurrency & Memory Anomalies
  if (navigator.hardwareConcurrency === 0 || navigator.hardwareConcurrency === undefined) {
    score += 20;
    reasons.push('invalid-hardware-concurrency');
  }

  // 3. Screen Dimension Checks (Headless scrapers often have 0x0 or odd screen geometry)
  if (window.outerWidth === 0 && window.outerHeight === 0) {
    score += 50;
    reasons.push('zero-outer-dimensions');
  }
  if (window.screen && (window.screen.width === 0 || window.screen.height === 0)) {
    score += 50;
    reasons.push('zero-screen-dimensions');
  }

  // 4. Broken Native Functions (Stealth plugins frequently override toString sloppily)
  try {
    if (navigator.permissions && navigator.permissions.query) {
      const permString = navigator.permissions.query.toString();
      if (!permString.includes('[native code]')) {
        score += 35;
        reasons.push('tampered-permissions-api');
      }
    }
  } catch {
    /* noop */
  }

  return {
    isBot: score >= 40,
    score,
    reasons,
  };
}

