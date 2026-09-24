# 站点兼容性：Cookie、单点登录与运行期改写

[← 回到 README](../README.md)

这一篇记录的是「为什么代理一个站点没那么简单」——每一节都对应一类真实踩过的坑，
以及网关为此做了什么。某个系统在网关下行为异常时，多半能在这里找到对应的形态。

## Cookie 与单点登录

两个只有代理才会遇到的问题，都会表现为“登录成功后立刻提示登录态失效”：

**一、Cookie 的字节必须原样透传。** Go 的 `net/http` 对 cookie 很严格：值里含非 ASCII 字符的
`Set-Cookie` 会被**整条丢弃**，含空格或逗号的值会被重新加引号，而 `Request.AddCookie` 会把
非法字节从值里剔除。任何一条都足以毁掉一个会话令牌——且只影响那些令牌恰好含这类字节的系统，
所以“并非所有系统都有这个问题”。网关因此把 Cookie 当文本处理：只改属性，`name=value` 原样搬运。

**二、域级 Cookie 的作用域没法直接搬过来。** SSO 的做法是给整个域签发一张 Cookie
（`Domain=.corp.example`），域内所有站点都能读到。但经过网关，这些站点要么共用一个浏览器源、
只靠路径隔离，要么各占一个子域——两种形态下都没有一个「域」能承载这张 Cookie 的跨主机效力。

所以带 `Domain` 的 Cookie **两边各放一份**：

- **服务端 Cookie 罐**按登录会话存放，在请求匹配该域的目标时回放。这是让“在 sso.corp.example
  登录、跳回 app.corp.example 后仍是登录态”成立的机制。
- **浏览器一份**，作用域收敛到该目标在网关下的位置：路径模式下钉在这个目标的路径上，
  子域名模式下钉在这个目标的主机上。站点自己的脚本要靠 `document.cookie` 读回自己的 Cookie，
  而经过网关，浏览器这一份是它们唯一看得见的——登录接口把令牌交给页面、页面下一个请求再读回来，
  靠的就是它。收敛作用域保证了它只回到设置它的那个站点，不会串到别的被代理站点。

细节：

- 服务端 Cookie 罐按登录会话隔离（键取会话令牌的哈希，不另存令牌本身），空闲 12 小时回收。
- `Domain` 与目标主机无关的 Cookie 被丢弃——真实浏览器同样会拒绝。
- `HttpOnly` 原样保留：源站标了 `HttpOnly`，浏览器那一份脚本照样读不到。
- 关闭登录（`-no-auth`）时没有会话可挂，只剩浏览器那一份。

### 回跳地址还原（redirect_uri / service / RelayState）

SSO 还有一处**响应改写修不好**的地方：应用跳转到身份提供方时，会带上一个说明“登录后回到哪里”的参数——
OIDC 的 `redirect_uri`、CAS 的 `service`、SAML 的 `RelayState`。这个值由应用从**浏览器当前地址**推导而来
（`window.location.origin`，或网关自己改写过的链接），经过网关后它就是网关地址：

```
应用侧真实行为   https://sso.corp.com/authorize?redirect_uri=https://soc.corp.com/callback   ✓
经过网关         https://sso.corp.com/authorize?redirect_uri=https://app.intra.corp.com/...  ✗ 校验不通过
```

身份提供方会拿它与为该应用**注册**的回调地址比对，对不上就直接拒绝登录。

方向与响应改写相反：请求**发往目标站点之前**，把参数里的网关地址还原成它所代表的真实地址。
提供方于是看到自己登记的那个回调，它答复的跳转再按常规改写回网关形式。三种形态都能还原：

| 参数里的地址 | 还原为 |
| --- | --- |
| `https://soc-corp-com-s.intra.corp.com/cb`（子域形式） | `https://soc.corp.com/cb` |
| `https://app.intra.corp.com/p/https/soc.corp.com/cb`（路径形式） | `https://soc.corp.com/cb` |
| `https://app.intra.corp.com/cb`（裸网关地址，即 `location.origin`） | 判定当前页面所属站点，见下 |

**还原后的地址必须保持原样的“形状”。** `redirect_uri` 是**逐字符**与注册值比对的
（RFC 6749 §3.1.2.3），`https://soc.corp.com` 与 `https://soc.corp.com/` 是两个不同的字符串。
解码得到的是一个"可以拿去发请求"的 URL，而请求总要有路径，于是一个裸的源会被补出一个
页面从未写过的 `/`——子域名模式下 `location.origin` 恰好就是裸源，因此**只有子域名模式**
会撞上这一条。还原时按被替换地址的结尾斜杠对齐，有就保留，没有就不加。

作用范围：查询串，以及 `application/x-www-form-urlencoded` 请求体（SAML/CAS 常用 POST 绑定，上限 1 MB）。
只改动值中**属于网关**的绝对地址，参数名、顺序与其余取值原样保留；不是网关的地址不动——登录表单里
`execution`、`authentication-session-id`、用户名口令这类参数不含地址，一个字节都不会被碰。

**裸网关地址怎么判定来源。** 子域形式与路径形式都自带目标，精确解码即可；只有 `location.origin`
这种裸地址什么都不带——路径模式下所有被代理的页面共用一个源，地址本身说明不了它代表哪个站点。
依次用两条线索：

1. **`Referer`**：最准，指明发起请求的正是哪个页面（含 iframe 内的页面）。
2. **该浏览器的访问轨迹**：不少企业系统会关掉 Referer（`Referrer-Policy: no-referrer`），此时按
   网关为每个浏览器记的**前后两个文档**判定——子资源归属当前文档，跳转到新文档则归属它的上一个文档。
   轨迹按登录会话隔离（未开登录时按来源 IP + User-Agent），空闲 2 小时回收，只在内存中。

两条都没有（浏览器开局第一条请求就直奔 SSO）时退回目标站点自身——此时来源本就无从得知。

后台“单点登录”一节控制它：默认**全部站点**生效（参数里出现网关地址本就不是源站期望的形态），
也可以改为**按域名**只对 `sso.corp.com` 这类身份提供方生效，或整体关闭。

### Cookie 命名空间：网关自己划清边界

网关的域通常**落在被代理站点的注册域之内**——一个机构只有一个注册域，不会为网关再注册一个。
于是浏览器会把它为那个更宽的域存下的所有 Cookie，也一并发给网关的主机：那是用户在**隧道之外**
访问别的系统时留下的。两件事会出问题：

1. **同名遮蔽。** 直接访问时，站点重发同名 Cookie 会**覆盖**旧的；经过网关，新的那份必须被收敛到
   网关主机或路径上，于是与作用域更宽的旧副本**并存**，一起发出（RFC 6265 §5.4：路径相同则先创建的
   在前）。只取第一个同名 Cookie 的服务端（Java 里很常见）读到的就是那份过期的，于是回
   "登录态已过期"——而浏览器手里明明攥着有效的令牌。
2. **越界转发。** 那些 Cookie 本与当前目标无关，却会被转发给它。

**名字是唯一能承载这个区分的东西**——浏览器只告诉网关名字和值，从不说这个 Cookie 存在哪个作用域下。
所以网关写进浏览器的 Cookie 一律加前缀 `__wvpn_`，回到站点时再摘掉，站点自始至终看不到它：

```
源站下发    Set-Cookie: galaxy_token=9d0b…; Domain=corp.com; Path=/
浏览器存的  __wvpn_galaxy_token=9d0b…            （隧道外那份 galaxy_token 原样留在 .corp.com）
发往源站    Cookie: galaxy_token=9d0b…           （只有本站自己的，用真实名字）
```

没有前缀的一律**不转发**：它不是网关放进去的，就不是这个站点的东西。注入脚本同样处理
`document.cookie`——读的时候只返回本站自己的、并摘掉前缀，写的时候补上前缀。所以页面看到的
始终是自己那套名字，既看不到隧道外的旧副本，也看不到别的系统的 Cookie。

**升级影响**：此前存进浏览器的 Cookie 没有前缀，升级后不再被转发，用户需要重新登录一次目标站点。

### 页面自己写的 Cookie

登录接口把令牌连同**域名和有效期**一起交给前端，由前端 `document.cookie` 自己写下——这是很常见的一种做法：

```
uopsAuthMap: { accessToken: "474ca9…", domain: "corp.example", cookieTime: 43200 }
```

浏览器只接受当前主机所属域的 `domain=`。页面经网关后位于网关主机上，不属于 `corp.example`，
这条写入会被**静默丢弃**——下一个请求便没有令牌，站点回"登录态已过期，请重新登录"。
所以注入脚本接管 `document.cookie` 的写入，按网关改写 `Set-Cookie` 的同一套规则翻译：

- `path` 改写到该目标在网关下的路径，站点之间不会互相看到 Cookie；
- 浏览器这一段是明文时去掉 `Secure`，`SameSite=None` 随之降为 `Lax`（否则浏览器整条丢弃）；
- 带 `domain=` 的另外交给网关的**域级 Cookie 罐**（`POST /_wv/cookie`），由它回放给该域下的其他主机——
  这正是 `userCenter` 指向同域另一台主机时仍能认这个令牌的原因。网关只接受目标自身能设置的域，
  且拒绝任何试图覆盖网关会话 Cookie 的写入。

### 不带 Cookie 的接口请求（`credentials: "omit"`）

不少单页应用登录后拿到的是**令牌**，存在前端、放进请求头发送，接口调用时干脆声明不带 Cookie：

```js
fetch("/dbocDirp/getAuthorInfo.json", { method: "POST", credentials: "omit",
  headers: { Authorization: "Bearer …" }, body })
```

直接访问没有任何问题。经过网关就不行了：网关认人靠的是它自己的会话 Cookie `wvsid`，
`omit` 连这个也去掉了，请求在网关的登录校验这一层就被拦下，返回
`401 {"ok":false,"error":"unauthenticated"}`——**根本到不了源站**，所以开了 `-log-headers`
也看不到这些接口。表现是页面能打开、静态资源都正常，只有接口全部 401。

注入脚本因此接管这类请求：发往本页同源（即网关自身）的 `omit` 请求改为带 Cookie 发出，
并加上标记头 `X-Wvpn-Credentials: omit`。网关见到标记，照常用 `wvsid` 做登录校验，然后
**把 `omit` 的本意还给源站**：

- 不转发任何 Cookie——浏览器里存的本站 Cookie、域级 Cookie 罐里的都不带；
- 响应里的 `Set-Cookie` 既不交给浏览器，也不进 Cookie 罐（`omit` 的响应本来就不会被存）；
- 标记头本身在转发前删掉，源站看不到。

所以源站收到的请求与直接访问时一致：只有令牌，没有 Cookie。`-log-headers` 下这类请求的
`Cookie` 与 `X-Wvpn-Credentials` 都会显示在 `(dropped)` 行里。

尚未覆盖的情形：

- **子域名模式下跨目标的 `omit` 请求**（页面在 A 站点、请求发往 B 站点的网关子域）：跨源请求
  带凭据需要 CORS 预检与 `Access-Control-Allow-Credentials` 配合，与同源情形不是一回事，暂不改写；
- `mode: "no-cors"` 的请求无法携带自定义头，按原样发出；
- `XMLHttpRequest` 同源时总会带 Cookie，不受 `withCredentials` 影响，本来就没有这个问题。

### location.origin 拼出来的地址

页面脚本极常见的一种写法：`fetch(location.origin + '/api/profile')`。在**路径模式**与**加密路径模式**下，
`location.origin` 是网关自己（所有被代理的页面共用一个源），拼出来的地址既不带 `/p/` 前缀也不带目标，
网关那个路径上什么都没有——页面于是报"加载失败"。**子域名模式没有这个问题**：那里每个目标有独立的源，
`location.origin` 本来就是站点自己。

两层处理：

- 注入脚本把这类地址读回它本来的意思——**同源但不带网关前缀的绝对地址**，等价于站点上的同一条路径，
  按当前页面所属站点重新编码。已经是网关地址的（`/p/…`、加密路径形式、`/_wv/` 资源）原样放行。
- 万一仍有漏网的（脚本加载前发出的请求、Worker 里发出的请求），网关对认不出的路径做兜底：按 `Referer`
  或该浏览器当前所在文档判定归属，307 重定向回正确的网关地址，并在日志里记一行
  `stray GET /api/profile -> http://soc.corp.com/api/profile`，便于排查还有哪些地址逃逸。

### `<base href>` 与相对地址的基准

页面可以用 `<base href="/ZULXYAIK8642/__public/">` 把相对地址的基准挪到别处，浏览器是认这个的。
基准差一段，相对地址就落到上一级目录去——`new URL("app/x.js", ".../__public")` 会把 `__public`
整段丢掉，站点于是对一个明明存在的文件回 404。

两侧都要认它：

- **服务端 HTML 改写**按文档里声明的 `<base>` 解析其后的引用；`<base>` 自身的 href 则按**文档**
  解析，而不是按它自己（否则 `<base href="__public/">` 会解析成 `__public/__public/`）。
- **注入脚本**解析运行时的相对地址时以 `document.baseURI` 为准（它已计入 `<base href>`），
  再映射回目标地址空间。此前它一律按文档自身的地址解析，单页应用在运行时动态加载的资源
  （single-spa、webpack 的 publicPath 等）就会整段丢失路径。

### 应用自己的基路径，与 location.pathname

有些站点自带一层基路径（`https://soc.corp.com/ZULXYAIK8642/`），并在启动时把自己导航到
"基路径 + 当前路径"。路径模式下 `location.pathname` 带着网关前缀，于是拼出来的是
`/ZULXYAIK8642/p/https/soc.corp.com/`——站点被要求打开一条把网关折进中段的路径，此后页面上
每一个相对地址都从这个错位的位置起算，资源全部落到 SPA 兜底的 HTML 上，浏览器便报
`Refused to execute script … MIME type ('text/html') is not executable`。

`location` 不可劫持，脚本层面拦不住这次读取。但**网关前缀出现在目标路径的中段一定是错的**，
而那段引用正好说明了页面本来想去哪里，于是网关把它拼回去（`/base` + `/rest`）并把浏览器
重定向过去——`location.pathname` 随之恢复正常，相对地址也就都对了。只有指向目标自身主机的
引用才会被拼合，免得误伤真的提供这种路径的站点。日志里记作
`unwrapped http://soc.corp.com/base/p/https/soc.corp.com/ -> http://soc.corp.com/base/`。

**有一类应用路径模式救不回来**：如果它要求 `location.pathname` **以**自己的基路径**开头**
（而不只是包含），路径模式下这个条件永远无法满足——它会不停地重新导航。这类站点请用
[子域名模式](url-modes.md)，那里 `location.pathname` 就是站点自己的路径，条件自然成立。
实测同一个应用：路径模式下反复跳转直至超时，子域名模式下一次加载成功。

### 赋值式跳转

`location.href = "https://sso.intra.com/"` 是拦不住的：该属性是 unforgeable 的，任何补丁都看不到这次赋值。
但**导航本身**能看到——Navigation API 的 `navigate` 事件对跨源导航同样触发，实测 `cancelable: true`
（`canIntercept` 为 false 不影响取消）。所以注入脚本会取消这次导航，改用网关地址重新发起：

```
location.href = "http://sso.intra.com/login"
   → navigate 事件（cancelable）→ preventDefault()
   → navigation.navigate("/p/http/sso.intra.com/login")
```

覆盖范围：Chromium 102+（Chrome / Edge）。Firefox 与 Safari 尚未提供该 API，因此还有一层兜底——
**在脚本执行之前就把地址改掉**：网关会改写脚本与 JSON 响应（含 HTML 内联脚本）中的绝对地址，
默认只改与当前站点**同注册域**的主机（`-js-rewrite related`），这正是 SSO 跳转发生的范围；
`all` 改写全部可代理地址，`off` 完全不动脚本。

之所以默认只改同域：脚本里的绝对地址未必是导航目标，也可能是用来比较的字符串，改写范围越大误伤越多。
只替换 `scheme://host` 部分，其后路径原样保留。

**改写保形：绝对地址仍是绝对地址。** 脚本会对它持有的地址做运算——拼到基路径后面、交给路由、拿去比较。
把绝对地址换成根相对路径会改变运算结果：常见的加载器写法是"绝对地址直接用，相对地址才拼自己的基路径"，
于是 `https://soc.corp.com/app/x.js` 变成 `/p/https/soc.corp.com/app/x.js` 后被当成相对地址，
拼出 `/ZULXYAIK8642/p/https/soc.corp.com/app/x.js` 这种双重编码的地址，站点按 SPA 兜底回一个 HTML，
浏览器便报 `Refused to execute script … MIME type ('text/html') is not executable`。
所以脚本里的绝对地址改写为**带网关源的绝对地址**（`https://app.intra.corp.com/p/https/soc.corp.com/…`）。
HTML 属性不受影响——那里由浏览器按文档解析，根相对形式更短也更稳。

两条路径实测（A/B 对照，浏览器真实执行）：

| | 赋值式跳转后所在位置 |
| --- | --- |
| v0.3.0（无本次修复） | `http://app.corp.example:9101/` —— **已离开网关** |
| 本版本（`-js-rewrite off`，仅靠 Navigation API） | `http://gw/p/http/app.corp.example:9101/` —— 仍在隧道内 |
| 本版本（`-js-rewrite related`） | 脚本里的地址在执行前已改为 `/p/http/sso.corp.example:9102/login?back=` |

仍然无解的情形：非 Chromium 浏览器 + 地址在运行时拼接（脚本里没有可改写的字面量）。
这种站点请用[子域名模式](url-modes.md)——注入脚本知道网关域名，运行期拼出的地址也会走子域形式。

## 自签名证书

内网站点用自签名或私有 CA 签发的证书是常态，直接拒绝会让网关没法用；而 `-insecure-tls`
是另一个极端——对所有目标静默接受任何证书。

网关的做法与浏览器一致：停下来，把证书摊开给你看（主体、颁发者、适用名称、有效期、SHA-256 指纹），
由你决定是否继续。确认之后，网关**只信任这一张证书**（按指纹匹配），而不是关闭该主机的校验——
证书一旦更换会再次询问。

- 信任只存在内存中，进程重启即失效。
- 确认接口只接受网关刚刚展示过的证书指纹（10 分钟内），避免被构造请求预置信任。
- 子资源请求（图片、脚本）不会渲染询问页，只返回明确的错误；询问只出现在页面跳转上。
- 需要对所有目标一律跳过校验时仍可用 `-insecure-tls`，但那会丢掉上面全部保护。

**注意**：确认是网关级的，任一登录用户确认后对所有用户生效（日志会记录是谁确认的）。
这在内网网关的使用场景下是合理的折中，但如果你的用户群不可信，请用 `-allow` 收窄可达范围。
