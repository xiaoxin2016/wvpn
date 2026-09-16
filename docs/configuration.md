# 配置

[← 回到 README](../README.md)

命令行参数只是**首次启动的种子**：写进配置文件之后，登录策略、访问策略、书签、SMTP、
网关地址与证书都以管理后台为准，改完立即生效、无需重启。

## 命令行参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-addr` | `:8080` | 监听地址 |
| `-tls-cert` / `-tls-key` | — | 证书文件；提供时**优先于后台配置的证书** |
| `-url-mode` | — | 首次启动时写入的 URL 模式：`plain` / `wrd` / `subdomain`；之后由管理后台接管 |
| `-url-key` | 见下文 | `wrd` 模式的 AES 密钥（16/24/32 字节），仅命令行可配 |
| `-base-domain` | — | 首次启动时写入的泛域名（目标子域挂在它下面），如 `intra.corp.com` |
| `-portal-host` | — | 首次启动时写入的门户主机名，留空即 `app.<泛域名>` |
| `-public-port` | — | 首次启动时写入的对外端口 |
| `-allow` / `-deny` | — | 目标主机白/黑名单，逗号分隔，按域名后缀匹配。这是**硬性边界**，管理后台无法放宽 |
| `-allow-private` | `false` | 允许访问环回/RFC1918/CGNAT 地址（内网网关通常需要开启，见安全须知）。链路本地与组播地址始终拒绝 |
| `-insecure-tls` | `false` | 不校验上游证书 |
| `-js-rewrite` | `related` | 脚本与 JSON 中绝对地址的改写范围：`off` / `related`（同注册域）/ `all` |
| `-max-rewrite-bytes` | `8MiB` | 超过此大小的响应体不改写，直接透传 |
| `-no-auth` | `false` | 关闭登录（仅供开发） |
| `-config` | `webvpn-config.json` | 管理后台可写的策略文件 |
| `-default-domain` / `-allow-user` / `-admin` | — | 策略文件不存在时的初始值 |
| `-session-ttl` / `-code-ttl` | `1h` / `5m` | 会话与验证码有效期；会话有效期之后由后台接管 |
| `-log-headers` | `false` | 排查用：记录发往上游的请求头与 `Set-Cookie`，见下文（明文记录凭据） |
| `-ignore-email` | `false` | **把验证码打印到控制台**，不发邮件 |
| `-smtp-addr` / `-smtp-user` / `-smtp-pass` / `-smtp-from` | — | SMTP 提交服务，作为管理后台未配置时的兜底；密码优先取环境变量 `WEBVPN_SMTP_PASS` |
| `-smtp-tls-mode` | `auto` | `auto`（支持 STARTTLS 就升级）/ `require` / `none` / `implicit`（465 直接 TLS） |
| `-smtp-allow-plaintext-auth` | `false` | 允许在未加密连接上发送 SMTP 账号密码 |
| `-smtp-helo` | — | EHLO 名称，部分中继拒绝默认值 |
| `-smtp-implicit-tls` | `false` | 直接 TLS（465）而非 STARTTLS（587） |
| `-name` | `WebVPN` | 门户标题 |
| `-bookmarks` | — | 书签 JSON 文件，仅在首次启动（策略文件中还没有书签时）导入一次，之后由管理后台接管 |
| `-trust-proxy-headers` | `false` | 无条件相信 `X-Real-IP` / `X-Forwarded-For`；来自**环回地址**的连接无论该参数如何都会读这两个头（本机 nginx 反代即属此列） |

`bookmarks.json` 的格式（仅用于首次导入，之后在管理后台里编辑）：

```json
[
  {"name": "常用系统", "items": [
    {"name": "内网门户", "url": "http://portal.corp.local/", "note": "说明文字，可省略"}
  ]}
]
```

## 非交互部署

参数一次性带齐，跳过初始化页面——适合配置管理工具铺开：

```bash
WEBVPN_SMTP_PASS='...' ./webvpn -addr 127.0.0.1:8080 \
  -smtp-addr smtp.example.com:587 -smtp-user no-reply@example.com -smtp-from no-reply@example.com \
  -default-domain example.com -allow-user '*@example.com' -admin 'ops@example.com' \
  -config /var/lib/webvpn/config.json -bookmarks /etc/webvpn/bookmarks.json
```

由网关自己承载 TLS（不经前置代理）时加上证书：

```bash
./webvpn -addr :443 -tls-cert /etc/ssl/webvpn.crt -tls-key /etc/ssl/webvpn.key ...
```

口令走环境变量 `WEBVPN_SMTP_PASS`，不要写进命令行——`ps` 看得见。

## 首次初始化

没有管理员的网关谁都登录不进去，而"第一个访问者自动成为管理员"对一台网关来说太危险——
端口一暴露就归先到的人。所以初始化由**启动日志中打印的一次性令牌**把关：能读到网关控制台，
就是运维本人，这也是此刻唯一存在的凭据。

流程：

1. 启动时若配置里没有管理员，日志打印 `/setup?token=…`（令牌 120 位随机，仅存于内存）；
2. 打开该链接，填写管理员邮箱、默认域、允许登录的账号与 SMTP；可先"发送测试邮件"验证发信；
3. 完成后跳转登录页，用该邮箱收验证码登录。

几点设计取舍：

- **令牌只给"配置"权限，不给"访问"权限**：初始化之后仍需通过邮箱验证码证明你控制那个邮箱。
- **令牌在管理员首次登录成功后才失效**，而不是提交表单即失效——否则 SMTP 填错一个字母就没人能进来了。
- 用启动参数（`-admin` / `-allow-user`）预置管理员时，不进入初始化模式，适合自动化部署。

## 邮件发送

验证码的投递方式按以下优先级决定：

1. `-ignore-email`：验证码打印到进程日志，**覆盖一切**，仅用于本地开发；
2. 管理后台"邮件发送"里配置的 SMTP（一旦填了服务器与发件人就生效，改完立刻生效，无需重启）；
3. 启动参数 `-smtp-addr` 等，作为后台尚未配置时的兜底。

三者皆无时进程会拒绝启动并给出提示——否则没人能收到验证码，等于服务不可用。

首次部署的引导顺序：用 `-ignore-email` 起一次，从控制台读验证码登录，在后台把 SMTP 填好，
然后去掉该参数重启。后台页面上有"保存并发送测试邮件"，走的是与真实验证码完全相同的发送路径。

支持的传输组合：

| 场景 | 配置 |
| --- | --- |
| 内网中继，25 端口，无认证 | 地址填 `relay:25`，用户名密码留空，模式 `auto` |
| 提交服务，587 + STARTTLS | 模式 `auto` 或 `require` |
| 提交服务，465 直接 TLS | 模式 `implicit` |
| 25 端口且必须认证 | 勾选“允许明文认证”，凭据将以明文经过网络 |

认证机制按服务器通告自动选择：未加密时优先 CRAM-MD5（口令不过网），否则 PLAIN / LOGIN
（`AUTH LOGIN` 是 Exchange 等旧中继的唯一选项，Go 标准库不实现，网关自己实现了）。

> 为什么不是直接用 `net/smtp.SendMail`：它在未加密连接上拒绝认证，只抛出 `unencrypted connection`，
> 既不说明原因也没有开关。默认拒绝是对的，无条件拒绝不是——25 端口的内网中继是常态。

几点与安全相关的设计：

- **密码不回显**：`GET /admin/api/config` 只返回 `password_set: true|false`，不返回密码本身；
  保存时留空表示"沿用已保存的密码"，另有显式的"清除已保存的密码"。
- **测试邮件只发给当前登录的管理员**，接口不接受收件人参数——否则这个表单就是一台开放的发信中继。
- **密码以明文存在配置文件里**（0600）。单机部署没有可用来加密它的密钥托管，与其做"看起来加密"
  的混淆不如说清楚：请给网关配一个专用发信账号或应用专用密码，不要用重要邮箱的主密码。

## 访问策略

管理后台的“访问策略”决定**普通用户**能通过网关访问哪些站点。它与启动参数是**两层**关系：
`-allow` / `-deny` 是运维设定的硬性边界，后台策略只能在这个边界内进一步收紧。

**管理员账号不受访问策略约束**——管理员可以随时改写这份清单，让它拦住自己没有意义。
但启动参数的硬边界与内网地址防护对管理员同样生效：那是网关所在主机的边界，不是后台的设置项。
换句话说，一个管理员账号等同于一张进入 `-allow` 范围内全网的通行证，请按特权账号管理。

| 模式 | 行为 |
| --- | --- |
| 不限制 | 只受启动参数与内网防护约束 |
| 白名单 | 仅允许访问站点清单命中的目标（清单不能为空） |
| 黑名单 | 站点清单命中的目标一律拒绝 |

站点清单每行一条，两种写法：

- **主机匹配式**：`oa.corp.local`（不含通配符时同时覆盖其子域，如 `x.oa.corp.local`）、
  `*.corp.local`、`git-*.corp.local`。在 DNS 解析之前按目标主机名匹配。
- **网段**：`10.0.0.0/8`、`fd00::/8`。在**解析出真实地址之后**匹配，因此可以拦下
  “域名看着人畜无害、实际指向内网”的情况，也可以用一条规则放行整个内网。

两个阶段都会判定：主机名阶段命中即可给出结论；白名单模式下主机名没命中但清单里有网段时，
判定推迟到连接前的地址阶段（因此错误可能表现为 502 而不是 403）。

需要留意的固有限制：仅按名字拦截时，用户可以用 IP 直连或换一个指向同一站点的域名绕开黑名单。
要真正封住一个网段，请写 CIDR 规则。

## 排查：`-log-headers`

站点在网关下行为异常、又看不出所以然时，用它把**网关发往上游的请求**记下来，和浏览器直连时的
请求逐条对比：

```bash
./webvpn -log-headers ...
```

每个被代理的请求会记三段：

```
upstream conn http://eiop.corp.com/uops/api/... -> 10.2.3.41:443 (reused=true)
upstream POST http://eiop.corp.com/uops/api/tacking/addTackingInfo.do
  Host: eiop.corp.com
  Cookie: JSESSIONID=2BFC9FA4...
  Origin: https://eiop.corp.com
  Referer: https://eiop.corp.com/
  (dropped) Connection: keep-alive
origin 200 http://eiop.corp.com/uopsLogin/uopsLogin.do
  (origin)  Set-Cookie: JSESSIONID=...; HttpOnly; Path=/
  (browser) Set-Cookie: JSESSIONID=...; HttpOnly; Path=/
```

- `upstream conn` 是这次请求**实际连到的后端地址**。站点在 SLB 后面、会话又是节点本地的时候，
  登录与后续请求落到不同节点就会表现为「Cookie 是对的，服务端说登录态过期」——看这一行能直接分辨。
- `upstream` 段是发出去的请求头，`(dropped)` 是浏览器发了、网关没有转发的。
- `origin` 段左边是源站下发的原始 `Set-Cookie`，右边是改写后给浏览器的，两相对照能看出作用域是否被改坏。

**它会把会话 Cookie 与令牌明文写进日志**，查完就关掉。

## 会话与来源 IP

后台「会话与来源 IP」一节，两项都即时生效。

### 会话有效期

默认 **1 小时**，指的是「多久没有使用就登出」。时间越短，会话 Cookie 万一被窃取，可用的窗口越小。

打开着的页面会在**临近到期前约一分钟**自动续期，所以正常使用不会被打断：门户、管理后台、
以及每个被代理页面里注入的脚本都会请求 `POST /_wv/session/renew`。该端点在网关应答的**每个主机**
上都可用——子域名模式下被代理的页面在自己的子域上，同源请求才带得上 Cookie。

续期同时**重新下发 Cookie**。这一步不能省：Cookie 自带有效期，浏览器被告知一小时后失效就会
如期丢弃，服务端单方面延长是没用的。

关掉标签页就没人续期了，到期即结束。范围 5–1440 分钟，留空沿用 `-session-ttl`。

### 来源 IP

默认**不向目标站点传递** `X-Forwarded-For`：网关的作用之一就是让目标站点看不到背后是谁，
内网地址也不宜随手外泄。目标站点需要按真实来源记录日志或做访问控制时再打开。

打开后传的是**网关判定出的那一个地址**（即后台活动会话里显示的那个，已按 `-trust-proxy-headers`
规则处理过前置代理），不是浏览器带来的整条链——那条链是客户端想写什么就是什么。
`X-Forwarded-Host` 与 `X-Forwarded-Proto` 始终不传：它们描述的是网关而非站点自身，传过去只会
让站点误判自己的地址。

## 登录与权限

- 登录页标题只有“登录”，**不出现任何产品名称，也不显示已配置的默认邮箱域**（占位符固定为 `user@domain.com`），
  避免扫描者从登录页反推出组织的邮件域；错误信息统一，不区分“账号不存在”与“无权限”，
  避免账号枚举（user enumeration）。默认域只在服务端补全，只填前缀依然可以登录。
- 验证码 6 位、内存中只存 SHA-256、默认 5 分钟过期、最多 5 次尝试、同一地址 60 秒内不重发，
  另有基于来源 IP 的滑动窗口限流。
- 会话 Cookie 为 `HttpOnly` + `SameSite=Lax`，HTTPS 下自动加 `Secure`；
  **该 Cookie 在转发上游前会被剥离**，代理目标看不到网关会话。
- 管理后台不允许把自己从管理员列表里删掉，防止自锁。
- 管理员豁免访问策略（见上一节），因此“谁是管理员”本身就是一项访问控制决策。
