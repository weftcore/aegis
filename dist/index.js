let u = !1, c = {}, a;
function b(e = {}) {
  if (u || typeof window > "u") return;
  u = !0, c = e;
  const r = !p();
  if (e.allowedOrigins && h({
    allowedOrigins: e.allowedOrigins,
    redirectUrl: e.unauthorizedRedirectUrl,
    allowLocalhostInDev: e.allowLocalhostInDev !== !1
  }), Array.isArray(e.freezeTargets))
    for (const t of e.freezeTargets)
      t && typeof t == "object" && f(t);
  r && (e.silenceConsole !== !1 && m(), e.antiDebug !== !1 && (a = g(e.antiDebugIntervalMs ?? 2e3)), e.antiSourceExtraction !== !1 && v(), e.antiHeadless !== !1 && w(), e.blockDevShortcuts !== !1 && y());
}
function S() {
  u = !1, a !== void 0 && (clearInterval(a), a = void 0), s.forEach((e) => e()), s.length = 0;
}
function h(e) {
  if (!(typeof window > "u"))
    try {
      if (window.self === window.top) return;
      const r = document.referrer ? new URL(document.referrer).origin : "";
      let t = !1;
      e.allowedOrigins instanceof RegExp ? t = e.allowedOrigins.test(r) : Array.isArray(e.allowedOrigins) && (t = e.allowedOrigins.some(
        (n) => r === n || r.endsWith("." + new URL(n).hostname)
      )), !t && e.allowLocalhostInDev && p() && (t = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(r)), t || (o("frame-violation", r), document.documentElement.innerHTML = "", e.redirectUrl && window.top && (window.top.location.href = e.redirectUrl));
    } catch {
      o("frame-violation", "cross-origin"), document.documentElement.innerHTML = "";
    }
}
function f(e) {
  Object.freeze(e);
  for (const r of Object.getOwnPropertyNames(e)) {
    const t = e[r];
    t && typeof t == "object" && !Object.isFrozen(t) && f(t);
  }
  return e;
}
function m() {
  if (typeof console > "u") return;
  const e = () => {
  }, r = ["log", "info", "debug", "table", "dir", "trace", "group", "groupEnd"];
  for (const t of r)
    try {
      console[t] = e;
    } catch {
    }
}
function g(e = 2e3) {
  const r = () => {
    const t = performance.now();
    try {
      (function() {
      }).constructor("debugger")();
    } catch {
    }
    const n = performance.now() - t;
    n > 80 && (o("debugger-detected", `latency=${n.toFixed(0)}ms`), d());
    try {
      const i = new Image();
      let l = !1;
      Object.defineProperty(i, "id", {
        get: () => (l = !0, "")
      }), console.debug(i), l && (o("debugger-detected", "console-inspect"), d());
    } catch {
    }
  };
  return r(), window.setInterval(r, e);
}
function d() {
  try {
    sessionStorage.clear();
  } catch {
  }
  try {
    localStorage.removeItem("TOKEN");
  } catch {
  }
  try {
    localStorage.removeItem("REFRESH_TOKEN");
  } catch {
  }
}
function v() {
  try {
    const e = Function.prototype.toString, r = function() {
      const t = e.call(this);
      return t.includes("[native code]") ? t : (o("source-extraction", "toString"), "function () { [secure] }");
    };
    Function.prototype.toString = r, r.toString = () => "function toString() { [native code] }";
  } catch {
  }
  try {
    const e = Error.prepareStackTrace;
    Error.prepareStackTrace = function(r, t) {
      if (e) {
        const n = e(r, t);
        return typeof n == "string" ? n.replace(/https?:\/\/[^\s)]+/g, "[redacted]") : n;
      }
      return r.toString();
    };
  } catch {
  }
  try {
    const e = /* @__PURE__ */ new Set([
      "authClient",
      "AuthProvider",
      "useAuth",
      "TOKEN",
      "REFRESH_TOKEN"
    ]), r = Object.keys;
    Object.keys = function(t) {
      const n = r.call(Object, t);
      return t === window ? n.filter((i) => !e.has(i)) : n;
    };
  } catch {
  }
  try {
    const e = new MutationObserver((r) => {
      for (const t of r)
        for (const n of Array.from(t.addedNodes))
          n instanceof HTMLScriptElement && n.src && !_(n.src) && (o("source-extraction", `injected-script: ${n.src}`), n.remove());
    });
    e.observe(document.documentElement, { childList: !0, subtree: !0 }), s.push(() => e.disconnect());
  } catch {
  }
}
function _(e) {
  try {
    return new URL(e).origin === window.location.origin;
  } catch {
    return !0;
  }
}
function w() {
  var t;
  const e = [];
  navigator.webdriver && e.push("webdriver"), ((t = navigator.plugins) == null ? void 0 : t.length) === 0 && e.push("no-plugins"), /HeadlessChrome/i.test(navigator.userAgent) && e.push("headless-ua"), !window.chrome && /Chrome/.test(navigator.userAgent) && e.push("fake-chrome");
  const r = [
    "__webdriver_evaluate",
    "__selenium_evaluate",
    "__webdriver_script_function",
    "__webdriver_script_func",
    "__webdriver_script_fn",
    "__fxdriver_evaluate",
    "_phantom",
    "__nightmare",
    "_selenium",
    "callPhantom",
    "callSelenium",
    "_Recaptcha",
    "__driver_unwrapped",
    "__webdriver_unwrapped",
    "__driver_evaluate",
    "__lastWatirAlert",
    "__lastWatirConfirm",
    "__lastWatirPrompt",
    "cdc_adoQpoasnfa76pfcZLmcfl_Array",
    "cdc_adoQpoasnfa76pfcZLmcfl_Promise",
    "cdc_adoQpoasnfa76pfcZLmcfl_Symbol"
  ];
  for (const n of r)
    (n in window || n in document) && e.push(n);
  navigator.permissions && navigator.permissions.query({ name: "notifications" }).then((n) => {
    Notification.permission === "denied" && n.state === "prompt" && e.push("perm-inconsistency"), e.length > 0 && o("headless-detected", e.join(", "));
  }).catch(() => {
  }), e.length > 0 && o("headless-detected", e.join(", "));
}
function y() {
  const e = (t) => {
    if (t.key === "F12") {
      t.preventDefault(), o("devtools-shortcut", "F12");
      return;
    }
    if (t.ctrlKey && t.shiftKey && ["I", "J", "C"].includes(t.key.toUpperCase())) {
      t.preventDefault(), o("devtools-shortcut", `Ctrl+Shift+${t.key.toUpperCase()}`);
      return;
    }
    if (t.ctrlKey && t.key.toUpperCase() === "U") {
      t.preventDefault(), o("devtools-shortcut", "Ctrl+U");
      return;
    }
  }, r = (t) => {
    t.preventDefault(), o("devtools-shortcut", "right-click");
  };
  document.addEventListener("keydown", e, { capture: !0 }), document.addEventListener("contextmenu", r, { capture: !0 }), s.push(() => {
    document.removeEventListener("keydown", e, { capture: !0 }), document.removeEventListener("contextmenu", r, { capture: !0 });
  });
}
const s = [];
function p() {
  var e;
  try {
    return typeof process < "u" && ((e = process.env) == null ? void 0 : e.NODE_ENV) !== "production";
  } catch {
    return !1;
  }
}
function o(e, r) {
  var t;
  (t = c.onViolation) == null || t.call(c, e, r);
}
export {
  f as deepFreeze,
  S as destroySecurityGuard,
  h as enforceFrameGuard,
  b as initSecurityGuard,
  g as startAntiDebug
};
