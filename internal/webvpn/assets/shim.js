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

  var ASSETS = "/_wv/";
  // The encoding in force. Only the plain form is ever produced here — it is
  // served on every gateway host — but a page under another one still carries
  // that codec's addresses, which must be recognised as the gateway's own.
  var MODE = cfg.m || "plain";
  // The gateway's own session cookie, which a proxied page must not touch.
  var SESSION = cfg.c || "";
  var COOKIE_URL = ASSETS + "cookie";
  // The space the gateway keeps this site's cookies in, so that cookies the
  // browser holds for the wider organisation domain — picked up outside the
  // tunnel — neither shadow them nor show up as this site's own.
  var COOKIE_PREFIX = cfg.k || "__wvpn_";
  // Mirror of the wrd path shape: /{scheme}[-{port}]/{hex}/...
  var WRD_PATH = /^\/(?:http|https|ws|wss)(?:-[0-9]{1,5})?\/[0-9a-f]+(?:\/|$)/i;
  var OPAQUE = /^(data|blob|javascript|mailto|tel|sms|about|magnet|ftp|file|chrome|chrome-extension|intent):/i;
  var PROXYABLE = { "http:": 1, "https:": 1, "ws:": 1, "wss:": 1 };

  // Under the sub-domain mode the gateway answers on a whole wildcard domain,
  // and every one of those hosts is already a gateway address.
  var BASE = cfg.b || "";
  var BASE_PORT = cfg.port || "";
  var BASE_TLS = cfg.s === "1";

  function isGatewayHost(host) {
    var name = host.split(":")[0].toLowerCase();
    return name === location.hostname.toLowerCase() ||
      (BASE !== "" && (name === BASE || name.slice(-(BASE.length + 1)) === "." + BASE));
  }

  // Mirror of the server-side label encoding, so an address built at runtime
  // looks exactly like one the gateway rewrote.
  function label(hostname, port, tls) {
    var out = hostname.replace(/-/g, "--").replace(/\./g, "-");
    if (port) out += "-p" + port;
    if (tls) out += "-s";
    return out;
  }

  // A path is the gateway's own when it carries the prefix targets are encoded
  // behind, or belongs to the gateway's assets.
  function isGatewayPath(p) {
    if (p.indexOf(PREFIX) === 0 || p.indexOf(ASSETS) === 0) return true;
    return MODE === "wrd" && WRD_PATH.test(p);
  }

  function pathForm(u) {
    return PREFIX + u.protocol.slice(0, -1) + "/" + u.host + u.pathname + u.search + u.hash;
  }

  function encode(u) {
    if (!PROXYABLE[u.protocol]) return null;
    if (BASE === "") return pathForm(u);

    var scheme = u.protocol.slice(0, -1);
    var tls = scheme === "https" || scheme === "wss";
    var port = u.port;
    if ((port === "80" && !tls) || (port === "443" && tls)) port = "";
    var name = u.hostname;
    if (name.indexOf(":") >= 0) return pathForm(u); // IPv6 literal
    var lab = label(name, port, tls);
    if (lab.length > 63) return pathForm(u);        // too long for a DNS label

    var gatewayScheme = (scheme === "ws" || scheme === "wss")
      ? (BASE_TLS ? "wss" : "ws")
      : (BASE_TLS ? "https" : "http");
    var host = lab + "." + BASE + (BASE_PORT ? ":" + BASE_PORT : "");
    return gatewayScheme + "://" + host + u.pathname + u.search + u.hash;
  }

  // refBase is what a relative reference is measured from. A page can move that
  // with <base href>, and the browser honours it. Measuring from the document's
  // own address instead quietly drops a path segment — the reference lands one
  // directory up, and the site answers 404 for something that exists.
  function refBase() {
    var u;
    try {
      var b = document.baseURI;
      if (!b) return base;
      u = new URL(b);
    } catch (e) {
      return base;
    }
    // Only an address of the gateway's can be read back into the target's terms.
    if (u.origin !== location.origin && !isGatewayHost(u.host)) return base;
    try {
      if (u.pathname.indexOf(PREFIX) === 0) {
        var parts = u.pathname.slice(PREFIX.length).split("/");
        if (parts.length < 2) return base;
        return new URL(parts[0] + "://" + parts[1] + "/" +
          parts.slice(2).join("/") + u.search);
      }
      // Under the sub-domain codec this origin belongs to the target, so the
      // path is already the target's own.
      return new URL(base.protocol + "//" + base.host + u.pathname + u.search);
    } catch (e) {
      return base;
    }
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
      u = new URL(s, refBase());
    } catch (e) {
      return ref;
    }
    if (u.origin === location.origin || isGatewayHost(u.host)) {
      // Under the sub-domain codec this origin belongs to the target itself, so
      // the address is already where it should be.
      if (BASE !== "" || isGatewayPath(u.pathname)) return ref;
      // Under the path codec every proxied page shares the gateway's origin, so
      // an address a page built from location.origin names the gateway rather
      // than the site — and the gateway has nothing at that path. Read it as
      // what the page meant: the same path on the site the page came from.
      try {
        u = new URL(u.pathname + u.search + u.hash, base);
      } catch (e) {
        return ref;
      }
    }
    var enc = encode(u);
    return enc === null ? ref : enc;
  }

  // wsRewrite keeps websocket URLs on the gateway's own scheme.
  function wsRewrite(ref) {
    var out = rewrite(ref);
    // The path form is relative to this origin; a websocket needs an absolute
    // ws(s) URL. The sub-domain form is already absolute.
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

  // Frameworks and single sign-on pages often set an absolute href or action
  // just before navigating, after the observer has already swept. Catching the
  // event itself is the last chance to keep the navigation on the gateway.
  document.addEventListener("click", function (e) {
    try {
      var el = e.target && e.target.closest && e.target.closest("a[href], area[href]");
      if (!el) return;
      var href = el.getAttribute("href");
      var out = rewrite(href);
      if (out !== href) el.setAttribute("href", out);
    } catch (err) {}
  }, true);

  function fixForm(form, submitter) {
    if (!form || !form.getAttribute) return;
    var action = form.getAttribute("action");
    if (action) {
      var out = rewrite(action);
      if (out !== action) form.setAttribute("action", out);
    }
    if (submitter && submitter.getAttribute) {
      var fa = submitter.getAttribute("formaction");
      if (fa) {
        var o = rewrite(fa);
        if (o !== fa) submitter.setAttribute("formaction", o);
      }
    }
  }

  document.addEventListener("submit", function (e) {
    try {
      fixForm(e.target, e.submitter);
    } catch (err) {}
  }, true);

  ["submit", "requestSubmit"].forEach(function (name) {
    patch(window.HTMLFormElement && HTMLFormElement.prototype, name, function (orig) {
      return function (submitter) {
        try {
          fixForm(this, submitter);
        } catch (e) {}
        return orig.apply(this, arguments);
      };
    });
  });

  // ---- navigation ----------------------------------------------------------

  // `location.href = "https://sso.example/"` cannot be intercepted: the
  // property is unforgeable, so no patch can see the assignment. The Navigation
  // API sees the navigation it produces, though — including the cross-origin
  // ones, which report canIntercept:false but are still cancelable. Cancelling
  // and re-issuing the navigation against the gateway is what keeps a single
  // sign-on hop from walking the browser out of the tunnel.
  if (window.navigation && navigation.addEventListener) {
    navigation.addEventListener("navigate", function (e) {
      try {
        if (!e.cancelable || e.navigationType === "traverse") return;
        var url = e.destination && e.destination.url;
        if (!url) return;
        var mapped = rewrite(url);
        if (typeof mapped !== "string" || mapped === url) return;
        // Already a gateway address: nothing to correct.
        if (isGatewayHost(new URL(url, location.href).host)) return;

        e.preventDefault();
        var go = function () {
          if (navigation.navigate) navigation.navigate(mapped);
          else location.assign(mapped);
        };
        // Starting a navigation from inside the handler is allowed, but
        // deferring keeps this out of the way of the cancelled one.
        setTimeout(go, 0);
      } catch (err) {}
    });
  }

  // ---- document.cookie -----------------------------------------------------
  //
  // A page that writes its own cookie names the site's domain in it: a login
  // hands the browser "accessToken=…; domain=corp.example" and expects it back
  // on every later request. Behind the gateway the page sits on the gateway's
  // host, which is not in that domain, so the browser drops the write without a
  // word — and the site reports the session as expired on the very next call.
  //
  // The attributes are therefore translated the same way the gateway translates
  // a Set-Cookie header: the path is scoped to where this target is served,
  // flags the browser leg cannot honour are dropped, and a domain-scoped cookie
  // is handed to the gateway as well, which keeps those server-side and replays
  // them to every host the domain covers.

  // cookiePath maps the path an origin scoped a cookie to onto the gateway.
  function cookiePath(p) {
    try {
      var u = new URL(p && p.charAt(0) === "/" ? p : "/", base);
      u.search = "";
      u.hash = "";
      var enc = encode(u);
      if (!enc) return "/";
      if (enc.charAt(0) === "/") return enc;
      return new URL(enc).pathname || "/";
    } catch (e) {
      return "/";
    }
  }

  // rewriteCookie returns the cookie to hand the browser, and reports a
  // domain-scoped one to the gateway. An empty string means: write nothing.
  function rewriteCookie(raw) {
    var parts = String(raw).split(";");
    var eq = parts[0].indexOf("=");
    var name = (eq < 0 ? parts[0] : parts[0].slice(0, eq)).trim();
    if (name === "") return "";
    // A page must not be able to overwrite the gateway's own session.
    if (SESSION !== "" && name === SESSION) return "";

    // The value keeps its bytes; only the name moves into the gateway's space.
    var out = [COOKIE_PREFIX + name + "=" + (eq < 0 ? "" : parts[0].slice(eq + 1))];
    var domain = "";
    var path = "/";
    var secure = false;
    var sameSiteNone = -1;
    for (var i = 1; i < parts.length; i++) {
      var piece = parts[i];
      var eq = piece.indexOf("=");
      var key = (eq < 0 ? piece : piece.slice(0, eq)).trim().toLowerCase();
      var val = eq < 0 ? "" : piece.slice(eq + 1).trim();
      if (key === "domain") {
        domain = val;
        continue; // this origin is not in that domain; the gateway keeps it
      }
      if (key === "path") {
        path = val;
        continue; // re-scoped below
      }
      if (key === "secure") {
        secure = true;
        if (location.protocol !== "https:") continue; // the browser leg is plain
      }
      if (key === "samesite" && val.toLowerCase() === "none") sameSiteNone = out.length;
      out.push(piece);
    }
    // SameSite=None is only honoured together with Secure.
    if (sameSiteNone >= 0 && !(secure && location.protocol === "https:")) {
      out[sameSiteNone] = " SameSite=Lax";
    }
    out.push(" Path=" + cookiePath(path));

    if (domain !== "") report(raw);
    return out.join(";");
  }

  // report hands a domain-scoped cookie to the gateway's own jar, which is the
  // only place a cookie for a whole domain can live behind one origin.
  function report(raw) {
    try {
      fetch(COOKIE_URL, {
        method: "POST",
        credentials: "same-origin",
        keepalive: true,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ t: base.href, c: String(raw) }),
      }).catch(function () {});
    } catch (e) {}
  }

  (function () {
    var proto = window.Document && Document.prototype;
    var desc = proto && Object.getOwnPropertyDescriptor(proto, "cookie");
    if (!desc || typeof desc.get !== "function" || typeof desc.set !== "function") return;
    try {
      Object.defineProperty(document, "cookie", {
        configurable: true,
        enumerable: !!desc.enumerable,
        get: function () {
          // Only this site's own cookies, under the names it knows them by.
          var raw = desc.get.call(this);
          if (!raw) return raw;
          var out = [];
          raw.split(";").forEach(function (pair) {
            var s = pair.trim();
            if (s.indexOf(COOKIE_PREFIX) === 0) out.push(s.slice(COOKIE_PREFIX.length));
          });
          return out.join("; ");
        },
        set: function (raw) {
          var next = rewriteCookie(raw);
          if (next !== "") desc.set.call(this, next);
        },
      });
    } catch (e) {}
  })();

  // ---- keeping the sign-in alive -------------------------------------------
  //
  // A sign-in lasts an hour, which bounds what a stolen session cookie is
  // worth. A page being read for longer than that is not idle, so it asks for
  // the sign-in to be extended shortly before it runs out. The request goes to
  // this page's own origin: under the sub-domain codec that is the proxied
  // host, and the gateway answers there too, which is what keeps the ask
  // same-origin and the cookie attached.
  //
  // Nothing is done when it has expired: the next thing the page asks for is
  // bounced to the sign-in page by the gateway, which is both correct and less
  // destructive than navigating away from whatever the reader was doing.
  if (SESSION !== "") {
    (function () {
      var timer = null;

      function schedule(seconds) {
        if (timer) clearTimeout(timer);
        var wait = Math.max(30, (seconds || 300) - 60);
        timer = setTimeout(renew, wait * 1000);
      }

      function renew() {
        fetch(ASSETS + "session/renew", {
          method: "POST",
          credentials: "same-origin",
          cache: "no-store",
        }).then(function (r) {
          if (r.status === 401) return null; // signed out; stop asking
          return r.json().then(function (j) { schedule(j && j.expires_in); });
        }).catch(function () {
          schedule(60); // a blip in the network is not an expiry
        });
      }

      renew();
      document.addEventListener("visibilitychange", function () {
        if (!document.hidden) renew();
      });
    })();
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
