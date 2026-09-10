// Client-side companion to the server-side HTML rewriter.
//
// Static markup is rewritten before it reaches the browser; this file covers
// what a page builds at runtime — fetch, XHR, WebSocket, DOM writes and
// history updates — by folding each URL back into the gateway's path space.
(function () {
  "use strict";

  var cfg = window.__WV__ || {};
  var PREFIX = cfg.p || "/p/";
  var base;
  try {
    base = new URL(cfg.t);
  } catch (e) {
    return; // no target: nothing sensible to do
  }

  var OPAQUE = /^(data|blob|javascript|mailto|tel|sms|about|magnet|ftp|file|chrome|chrome-extension|intent):/i;
  var PROXYABLE = { "http:": 1, "https:": 1, "ws:": 1, "wss:": 1 };

  function encode(u) {
    if (!PROXYABLE[u.protocol]) return null;
    return PREFIX + u.protocol.slice(0, -1) + "/" + u.host + u.pathname + u.search + u.hash;
  }

  // rewrite maps one reference onto the gateway, returning the input unchanged
  // whenever it is already a gateway reference or cannot be proxied.
  function rewrite(ref) {
    if (ref === null || ref === undefined) return ref;
    var s = String(ref);
    if (!s || s.charAt(0) === "#" || OPAQUE.test(s)) return ref;
    if (s.indexOf(PREFIX) === 0) return ref;
    var u;
    try {
      u = new URL(s, base);
    } catch (e) {
      return ref;
    }
    if (u.origin === location.origin) return ref; // already ours
    var enc = encode(u);
    return enc === null ? ref : enc;
  }

  // wsRewrite keeps websocket URLs on the gateway's own scheme.
  function wsRewrite(ref) {
    var out = rewrite(ref);
    if (typeof out !== "string" || out.indexOf(PREFIX) !== 0) return out;
    var scheme = location.protocol === "https:" ? "wss:" : "ws:";
    return scheme + "//" + location.host + out;
  }

  // absolute resolves a gateway-relative reference back to the target URL, used
  // to keep `base` in step with SPA navigation.
  function retarget(ref) {
    try {
      var u = new URL(String(ref), location.href);
      if (u.origin !== location.origin) return;
      var rest = u.pathname.indexOf(PREFIX) === 0 ? u.pathname.slice(PREFIX.length) : null;
      if (rest === null) return;
      var parts = rest.split("/");
      if (parts.length < 2) return;
      base = new URL(parts[0] + "://" + parts[1] + "/" + parts.slice(2).join("/") + u.search);
    } catch (e) {
      /* leave base as it was */
    }
  }

  function patch(obj, name, make) {
    if (!obj) return;
    try {
      var orig = obj[name];
      if (typeof orig !== "function") return;
      obj[name] = make(orig);
      if (orig.prototype) obj[name].prototype = orig.prototype;
    } catch (e) {
      /* a frozen builtin is not worth failing the page over */
    }
  }

  // ---- network APIs --------------------------------------------------------

  patch(window, "fetch", function (orig) {
    return function (input, init) {
      try {
        if (typeof Request !== "undefined" && input instanceof Request) {
          var url = rewrite(input.url);
          if (url !== input.url) input = new Request(url, input);
        } else {
          input = rewrite(input);
        }
      } catch (e) {}
      return orig.call(this, input, init);
    };
  });

  patch(window.XMLHttpRequest && XMLHttpRequest.prototype, "open", function (orig) {
    return function (method, url) {
      var args = Array.prototype.slice.call(arguments);
      args[1] = rewrite(url);
      return orig.apply(this, args);
    };
  });

  patch(window.navigator, "sendBeacon", function (orig) {
    return function (url, data) {
      return orig.call(this, rewrite(url), data);
    };
  });

  if (window.WebSocket) {
    var NativeWS = window.WebSocket;
    var WrappedWS = function (url, protocols) {
      return protocols === undefined ? new NativeWS(wsRewrite(url)) : new NativeWS(wsRewrite(url), protocols);
    };
    WrappedWS.prototype = NativeWS.prototype;
    ["CONNECTING", "OPEN", "CLOSING", "CLOSED"].forEach(function (k) {
      WrappedWS[k] = NativeWS[k];
    });
    try {
      window.WebSocket = WrappedWS;
    } catch (e) {}
  }

  if (window.EventSource) {
    var NativeES = window.EventSource;
    var WrappedES = function (url, init) {
      return new NativeES(rewrite(url), init);
    };
    WrappedES.prototype = NativeES.prototype;
    try {
      window.EventSource = WrappedES;
    } catch (e) {}
  }

  patch(window, "open", function (orig) {
    return function (url) {
      var args = Array.prototype.slice.call(arguments);
      if (args.length) args[0] = rewrite(url);
      return orig.apply(this, args);
    };
  });

  // ---- DOM writes ----------------------------------------------------------

  var URL_ATTRS = {
    src: 1, href: 1, action: 1, formaction: 1, poster: 1, data: 1,
    "xlink:href": 1, background: 1, cite: 1
  };

  patch(Element.prototype, "setAttribute", function (orig) {
    return function (name, value) {
      var key = String(name).toLowerCase();
      if (URL_ATTRS[key]) value = rewrite(value);
      else if (key === "srcset" || key === "imagesrcset") value = rewriteSrcset(value);
      return orig.call(this, name, value);
    };
  });

  patch(Element.prototype, "setAttributeNS", function (orig) {
    return function (ns, name, value) {
      var key = String(name).toLowerCase();
      if (URL_ATTRS[key] || key === "href") value = rewrite(value);
      return orig.call(this, ns, name, value);
    };
  });

  function rewriteSrcset(value) {
    if (!value) return value;
    return String(value)
      .split(",")
      .map(function (part) {
        var m = part.match(/^(\s*)(\S+)(\s*.*)$/);
        return m ? m[1] + rewrite(m[2]) + m[3] : part;
      })
      .join(",");
  }

  // Property assignments (img.src = ...) bypass setAttribute, so wrap the
  // accessors the elements that matter inherit.
  [
    [window.HTMLImageElement, "src"], [window.HTMLImageElement, "srcset"],
    [window.HTMLScriptElement, "src"], [window.HTMLIFrameElement, "src"],
    [window.HTMLEmbedElement, "src"], [window.HTMLMediaElement, "src"],
    [window.HTMLSourceElement, "src"], [window.HTMLSourceElement, "srcset"],
    [window.HTMLTrackElement, "src"], [window.HTMLInputElement, "src"],
    [window.HTMLAnchorElement, "href"], [window.HTMLLinkElement, "href"],
    [window.HTMLAreaElement, "href"], [window.HTMLFormElement, "action"],
    [window.HTMLObjectElement, "data"]
  ].forEach(function (pair) {
    var ctor = pair[0], prop = pair[1];
    if (!ctor) return;
    try {
      var desc = Object.getOwnPropertyDescriptor(ctor.prototype, prop);
      if (!desc || !desc.set || !desc.configurable) return;
      var isSet = prop === "srcset";
      Object.defineProperty(ctor.prototype, prop, {
        configurable: true,
        enumerable: desc.enumerable,
        get: desc.get,
        set: function (v) {
          desc.set.call(this, isSet ? rewriteSrcset(v) : rewrite(v));
        }
      });
    } catch (e) {}
  });

  // innerHTML and friends produce nodes without going through either hook, so
  // sweep whatever appears.
  if (window.MutationObserver) {
    var ATTRS = ["src", "href", "action", "poster", "data", "srcset"];
    var fix = function (el) {
      if (!el || el.nodeType !== 1) return;
      for (var i = 0; i < ATTRS.length; i++) {
        var name = ATTRS[i];
        if (!el.hasAttribute || !el.hasAttribute(name)) continue;
        var v = el.getAttribute(name);
        var out = name === "srcset" ? rewriteSrcset(v) : rewrite(v);
        if (out !== v) el.setAttribute(name, out);
      }
    };
    var sweep = function (root) {
      fix(root);
      if (root.querySelectorAll) {
        var found = root.querySelectorAll("[src],[href],[action],[poster],[data],[srcset]");
        for (var i = 0; i < found.length; i++) fix(found[i]);
      }
    };
    try {
      new MutationObserver(function (records) {
        for (var i = 0; i < records.length; i++) {
          var added = records[i].addedNodes;
          for (var j = 0; j < added.length; j++) sweep(added[j]);
        }
      }).observe(document.documentElement, { childList: true, subtree: true });
    } catch (e) {}
  }

  // ---- history -------------------------------------------------------------

  ["pushState", "replaceState"].forEach(function (name) {
    patch(window.history, name, function (orig) {
      return function (state, title, url) {
        if (url !== undefined && url !== null) {
          var next = rewrite(url);
          var r = orig.call(this, state, title, next);
          retarget(next);
          return r;
        }
        return orig.apply(this, arguments);
      };
    });
  });

  patch(window.Location && Location.prototype, "assign", function (orig) {
    return function (url) {
      return orig.call(this, rewrite(url));
    };
  });
  patch(window.Location && Location.prototype, "replace", function (orig) {
    return function (url) {
      return orig.call(this, rewrite(url));
    };
  });

  // Expose the helpers for pages (and operators) that need to convert by hand.
  try {
    Object.defineProperty(window, "__wvRewrite", { value: rewrite });
    Object.defineProperty(window, "__wvTarget", { get: function () { return base.href; } });
  } catch (e) {}
})();
