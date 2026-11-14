/**
 * @weftcore/aegis - Advanced Hardware & Stealth Bot Fingerprinting
 * 
 * Deeply evaluates hardware characteristics that headless engines, scrapers,
 * and virtualization clouds cannot spoof without detection:
 * 1. WebGL Software vs Hardware Rasterizer & Shader Floating-Point Precision
 * 2. AudioContext DSP floating-point rendering variance across physical sound drivers
 * 3. 2D Canvas Subpixel Geometry & Font Winding Rules
 * 4. Permissions API Prototype Integrity & Native Function Verification
 * 5. Screen, Viewport, and Hardware Concurrency Consistency
 */

export interface BotDetectionResult {
  isBot: boolean;
  score: number; // 0 (human) to 100 (confirmed bot)
  reasons: string[];
  fingerprintHash?: string;
}

/**
 * FNV-1a 32-bit fast hashing algorithm for canvas and audio fingerprints.
 */
function fnv1a(str: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
  }
  return (hash >>> 0).toString(16);
}

/**
 * Generates an AudioContext DSP floating-point fingerprint.
 * Physical sound drivers have minute floating-point rounding variances that
 * cloud servers (AWS/GCP/Docker headless) lack or render uniformly.
 */
function getAudioFingerprint(): Promise<string> {
  return new Promise((resolve) => {
    try {
      const AudioContextClass =
        window.AudioContext ||
        (window as any).webkitAudioContext ||
        (window as any).OfflineAudioContext;

      if (!AudioContextClass) {
        return resolve('audio-unavailable');
      }

      // Render 44100Hz audio buffer through an oscillator and dynamics compressor
      const ctx = new (window.OfflineAudioContext || (window as any).webkitOfflineAudioContext)(1, 44100, 44100);
      const osc = ctx.createOscillator();
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(10000, ctx.currentTime);

      const comp = ctx.createDynamicsCompressor();
      comp.threshold.setValueAtTime(-50, ctx.currentTime);
      comp.knee.setValueAtTime(40, ctx.currentTime);
      comp.ratio.setValueAtTime(12, ctx.currentTime);
      comp.attack.setValueAtTime(0, ctx.currentTime);
      comp.release.setValueAtTime(0.25, ctx.currentTime);

      osc.connect(comp);
      comp.connect(ctx.destination);
      osc.start(0);

      ctx.startRendering().then((buffer: AudioBuffer) => {
        let sum = 0;
        const channelData = buffer.getChannelData(0);
        for (let i = 4500; i < 5000; i++) {
          sum += Math.abs(channelData[i]);
        }
        resolve(sum.toFixed(6));
      }).catch(() => resolve('audio-render-failed'));
    } catch {
      resolve('audio-error');
    }
  });
}

/**
 * Generates a 2D Canvas subpixel rendering fingerprint.
 */
function getCanvasFingerprint(): string {
  try {
    const canvas = document.createElement('canvas');
    canvas.width = 200;
    canvas.height = 50;
    const ctx = canvas.getContext('2d');
    if (!ctx) return 'no-canvas';

    ctx.textBaseline = 'top';
    ctx.font = "14px 'Arial', sans-serif";
    ctx.textBaseline = 'alphabetic';
    ctx.fillStyle = '#f60';
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = '#069';
    ctx.fillText('Aegis<shield>@123', 2, 15);
    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
    ctx.fillText('Aegis<shield>@123', 4, 17);

    return fnv1a(canvas.toDataURL());
  } catch {
    return 'canvas-error';
  }
}

/**
 * Evaluates hardware and browser characteristics to produce a bot probability score.
 */
export function detectStealthBot(): BotDetectionResult {
  if (typeof window === 'undefined') {
    return { isBot: false, score: 0, reasons: [] };
  }

  const reasons: string[] = [];
  let score = 0;

  // 1. WebGL Software Renderer & Virtualization Check
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (gl) {
      const debugInfo = (gl as WebGLRenderingContext).getExtension('WEBGL_debug_renderer_info');
      if (debugInfo) {
        const renderer = (gl as WebGLRenderingContext).getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || '';
        const vendor = (gl as WebGLRenderingContext).getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || '';

        // Known virtualized/cloud software GPU signatures
        const virtualGpus = [
          'SwiftShader',
          'llvmpipe',
          'VirtualBox',
          'VMware',
          'Mesa OffScreen',
          'Microsoft Basic Render',
          'Parallels',
          'Bochs',
        ];
        for (const gpu of virtualGpus) {
          if (renderer.toLowerCase().includes(gpu.toLowerCase()) || vendor.toLowerCase().includes(gpu.toLowerCase())) {
            score += 50;
            reasons.push(`software-gpu: ${gpu}`);
            break;
          }
        }
      }

      // Check shader float precision (software renderers often have reduced precision)
      const precision = (gl as WebGLRenderingContext).getShaderPrecisionFormat(
        (gl as WebGLRenderingContext).FRAGMENT_SHADER,
        (gl as WebGLRenderingContext).HIGH_FLOAT
      );
      if (precision && precision.precision === 0) {
        score += 30;
        reasons.push('zero-high-float-precision');
      }
    } else {
      score += 20;
      reasons.push('no-webgl');
    }
  } catch {
    /* noop */
  }

  // 2. Headless Flags & Automation Properties
  if (navigator.webdriver) {
    score += 70;
    reasons.push('navigator.webdriver=true');
  }

  if (/HeadlessChrome/i.test(navigator.userAgent)) {
    score += 80;
    reasons.push('headless-ua');
  }

  // 3. Known Automation & Stealth Scraper Injections
  const automationGlobals = [
    '__webdriver_evaluate',
    '__selenium_evaluate',
    '__webdriver_script_function',
    '__webdriver_script_func',
    '__webdriver_script_fn',
    '__fxdriver_evaluate',
    '_phantom',
    '__nightmare',
    '_selenium',
    'callPhantom',
    'callSelenium',
    '_Recaptcha',
    '__driver_unwrapped',
    '__webdriver_unwrapped',
    '__driver_evaluate',
    '__lastWatirAlert',
    '__lastWatirConfirm',
    '__lastWatirPrompt',
    'cdc_adoQpoasnfa76pfcZLmcfl_Array',
    'cdc_adoQpoasnfa76pfcZLmcfl_Promise',
    'cdc_adoQpoasnfa76pfcZLmcfl_Symbol',
  ];

  for (const g of automationGlobals) {
    if (g in window || (document && g in document)) {
      score += 60;
      reasons.push(`automation-global: ${g}`);
      break;
    }
  }

  // 4. Hardware Concurrency & Memory Anomalies
  if (navigator.hardwareConcurrency === 0 || navigator.hardwareConcurrency === undefined) {
    score += 25;
    reasons.push('invalid-hardware-concurrency');
  }

  // 5. Screen & Viewport Consistency
  if (window.outerWidth === 0 && window.outerHeight === 0) {
    score += 60;
    reasons.push('zero-outer-dimensions');
  }
  if (window.screen && (window.screen.width === 0 || window.screen.height === 0)) {
    score += 60;
    reasons.push('zero-screen-dimensions');
  }

  // 6. Permissions API Prototype Integrity
  // Stealth plugins (like puppeteer-extra-plugin-stealth) often tamper with navigator.permissions.query
  try {
    if (navigator.permissions && typeof (navigator.permissions as any).query === 'function') {
      const permProto = Object.getPrototypeOf(navigator.permissions);
      const permDesc = Object.getOwnPropertyDescriptor(permProto, 'query');
      if (permDesc && typeof permDesc.value === 'function') {
        const fnStr = permDesc.value.toString();
        if (!fnStr.includes('[native code]')) {
          score += 40;
          reasons.push('tampered-permissions-api');
        }
      }
    }
  } catch {
    /* noop */
  }

  // 7. Touch Points vs Mobile UA Inconsistency
  const isMobileUa = /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
  if (isMobileUa && navigator.maxTouchPoints === 0) {
    score += 35;
    reasons.push('mobile-ua-without-touch');
  }

  const canvasFp = getCanvasFingerprint();

  return {
    isBot: score >= 40,
    score: Math.min(score, 100),
    reasons,
    fingerprintHash: fnv1a(`${canvasFp}_${navigator.hardwareConcurrency}_${window.screen?.width}x${window.screen?.height}`),
  };
}

export { getAudioFingerprint, getCanvasFingerprint };
