# WebVPN

一个用 Go 实现的 WebVPN 网关：浏览器用邮箱验证码登录后，在门户里输入任意 http/https 地址，
由网关代为访问并改写响应，使整个站点后续的请求都回流到网关。本质上是一个**按目标动态路由的
反向代理 + 内容改写器**，不需要客户端安装任何东西。

```
浏览器 ──TLS──> WebVPN 网关 ──> 目标站点 (http/https/ws/wss)
          登录态          URL 编解码 + HTML/CSS 改写 + 运行期 JS 补丁
```

## 功能

- **反向代理**：任意 http/https 目标，支持查询串、跳转、Cookie、gzip、SSE 与 WebSocket 升级。
- **三种 URL 编码模式**（可插拔 `Codec`）：
  | 模式 | 形态 | 说明 |
  | --- | --- | --- |
  | `plain`（默认） | `/p/https/example.com/path?q=1` | 可读、易调试，单域名即可部署 |
  | `wrd` | `/https/<hex(iv)+hex(enc(host))>/path` | 目标主机名不出现在地址栏；形态对齐国内高校常见商用产品 |
  | `subdomain` | `http://a--b-example-com-s.<base>/path` | 每个目标独立浏览器 Origin，隔离最好；需要泛域名 DNS 与泛域名证书 |
- **内容改写**：HTML（`href/src/srcset/action/formaction/poster/data/xlink:href/style/<base>/meta refresh` 等）、
  CSS（`url()` / `@import`）、`Location` 与 `Link` 响应头、`Set-Cookie` 作用域。
- **运行期补丁**（注入的 `shim.js`）：`fetch`、`XMLHttpRequest`、`WebSocket`、`EventSource`、
  `sendBeacon`、`window.open`、`setAttribute`、元素 `src/href` 属性写入、`history.pushState/replaceState`，
  以及针对 `innerHTML` 生成节点的 `MutationObserver` 兜底。
- **邮箱验证码登录**：可配置默认域（只填前缀自动补全），会话保存在内存中，滑动续期。
- **管理后台**：`/admin` 配置默认邮箱域、允许登录账号（支持 `*` / `?` 通配）、管理员列表，并查看/注销活动会话。
- **SSRF 防护**：默认拒绝环回、RFC1918、链路本地、CGNAT、组播地址，且在 `net.Dialer.Control`
  中对**实际解析结果**再校验一次，因此 DNS 重绑定（DNS rebinding）同样被拦下。

## 界面

登录页只有一个邮箱输入框：既不出现产品名称，也不出现默认邮箱域，
对未认证访问者不暴露任何组织信息。

<p align="center">
  <img src="docs/screenshots/login.png" alt="登录页" width="330">
  <img src="docs/screenshots/login-code.png" alt="验证码" width="330">
</p>

登录后的门户：协议选择 + 地址栏直达，下面是最近访问（仅存于本地浏览器）与运维配置的常用链接。

![门户](docs/screenshots/portal.png)

管理后台：默认邮箱域、允许登录账号（通配符）、管理员列表，以及活动会话的查看与注销。

![管理后台](docs/screenshots/admin.png)

## 快速开始

```bash
go build -o webvpn ./cmd/webvpn

# 本地试跑：验证码打印到控制台，允许访问内网地址
./webvpn -addr 127.0.0.1:8080 \
       -ignore-email \
       -allow-private \
       -default-domain test.com \
       -allow-user '*@test.com' \
       -admin 'root@test.com'
```

打开 <http://127.0.0.1:8080/>，输入 `root`（会被补全为 `root@test.com`），
在启动终端里查看验证码，登录后即可在门户中输入目标地址。

生产环境用 SMTP 发信：

```bash
WEBVPN_SMTP_PASS='...' ./webvpn -addr :443 \
  -tls-cert /etc/ssl/webvpn.crt -tls-key /etc/ssl/webvpn.key \
  -smtp-addr smtp.example.com:587 -smtp-user no-reply@example.com -smtp-from no-reply@example.com \
  -default-domain example.com -allow-user '*@example.com' -admin 'ops@example.com' \
  -config /var/lib/webvpn/config.json -bookmarks /etc/webvpn/bookmarks.json
```

## 命令行参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-addr` | `:8080` | 监听地址 |
| `-tls-cert` / `-tls-key` | — | 同时提供时以 HTTPS 提供服务 |
| `-url-mode` | `plain` | `plain` / `wrd` / `subdomain` |
| `-url-key` | 见下文 | `wrd` 模式的 AES 密钥（16/24/32 字节） |
| `-base-domain` / `-public-port` | — | `subdomain` 模式的泛域名与对外端口 |
| `-allow` / `-deny` | — | 目标主机白/黑名单，逗号分隔，按域名后缀匹配 |
| `-allow-private` | `false` | 允许访问环回/RFC1918/CGNAT 地址（内网网关通常需要开启，见安全须知）。链路本地与组播地址始终拒绝 |
| `-insecure-tls` | `false` | 不校验上游证书 |
| `-max-rewrite-bytes` | `8MiB` | 超过此大小的响应体不改写，直接透传 |
| `-no-auth` | `false` | 关闭登录（仅供开发） |
| `-config` | `webvpn-config.json` | 管理后台可写的策略文件 |
| `-default-domain` / `-allow-user` / `-admin` | — | 策略文件不存在时的初始值 |
| `-session-ttl` / `-code-ttl` | `12h` / `5m` | 会话与验证码有效期 |
| `-ignore-email` | `false` | **把验证码打印到控制台**，不发邮件 |
| `-smtp-addr` / `-smtp-user` / `-smtp-pass` / `-smtp-from` | — | SMTP 提交服务；密码优先取环境变量 `WEBVPN_SMTP_PASS` |
| `-smtp-implicit-tls` | `false` | 直接 TLS（465）而非 STARTTLS（587） |
| `-name` / `-bookmarks` | `WebVPN` | 门户标题与常用链接文件 |
| `-trust-forwarded-for` | `false` | 从 `X-Forwarded-For` 取客户端 IP（仅在自有反代之后开启） |

`bookmarks.json` 的格式：

```json
[
  {"name": "常用系统", "items": [
    {"name": "内网门户", "url": "http://portal.corp.local/", "note": "说明文字，可省略"}
  ]}
]
```

## 登录与权限

- 登录页**不出现任何产品名称，也不显示已配置的默认邮箱域**（占位符固定为 `user@domain.com`），
  避免扫描者从登录页反推出组织的邮件域；错误信息统一，不区分“账号不存在”与“无权限”，
  避免账号枚举（user enumeration）。默认域只在服务端补全，只填前缀依然可以登录。
- 验证码 6 位、内存中只存 SHA-256、默认 5 分钟过期、最多 5 次尝试、同一地址 60 秒内不重发，
  另有基于来源 IP 的滑动窗口限流。
- 会话 Cookie 为 `HttpOnly` + `SameSite=Lax`，HTTPS 下自动加 `Secure`；
  **该 Cookie 在转发上游前会被剥离**，代理目标看不到网关会话。
- 管理后台不允许把自己从管理员列表里删掉，防止自锁。

## 安全须知（部署前请读完）

这是一个**功能完整但刻意保持简单**的实现，以下取舍是显式的，不是遗漏：

1. **网关本身就是一台开放代理**。务必保留登录（不要用 `-no-auth`），
   并用 `-allow` 把可达目标收敛到确实需要的网段/域名。
2. **`-allow-private` 会让网关成为进入内网的跳板**。开启前先确认 `-allow` 已配置，
   否则任何登录用户都能拿它扫内网。链路本地（含云元数据 `169.254.169.254` / `fe80::/10`）
   与组播地址无论是否开启该开关都始终拒绝。
3. **响应中的 CSP、X-Frame-Options、HSTS 等安全响应头会被剥离**。这是所有 WebVPN 类产品的
   共同代价：不剥离，改写后的页面就无法从网关域加载自身资源。后果是被代理站点失去这些浏览器侧防护，
   且在 `plain` / `wrd` 模式下所有目标共享同一个浏览器 Origin —— 一个被代理站点的 XSS
   可以读取同域下其它被代理站点的页面内容。**需要强隔离时请使用 `subdomain` 模式。**
4. **Cookie 隔离靠路径**（`plain` / `wrd` 模式）。因此 `Domain=.example.com` 这类跨子域共享的
   Cookie 会退化为按主机隔离；`subdomain` 模式没有这个问题。
5. **CSRF 边界被弱化**：`Origin` / `Referer` 会被改写成目标站点自身的值，被代理站点的同源
   校验因此对网关“看起来是同源的”。
6. **`wrd` 模式的默认密钥是公开值**（`wrdvpnisthebest!`，来自社区逆向资料），只是混淆不是保密；
   要让 URL 只有本网关能解，请用 `-url-key` 换成自有密钥。
7. **`-ignore-email` 会把验证码打到控制台**，等于把登录凭据写进日志，仅限本地开发。

它**不能**替代真正的 VPN：只处理 HTTP 语义的流量，不承载任意 TCP/UDP；
对强依赖自身域名、使用 Service Worker、WebAssembly 里硬编码地址或做 TLS pinning 的站点会失效。

## 代码结构

```
cmd/webvpn/main.go          命令行、装配、优雅退出
internal/webvpn/codec.go    三种 URL 编解码（plain / wrd / subdomain）
internal/webvpn/rewrite.go  HTML / CSS 改写（基于 x/net/html tokenizer，未改动的 token 原样透传）
internal/webvpn/proxy.go    ReverseProxy 装配、请求/响应改写、Cookie 重定域
internal/webvpn/guard.go    目标主机与地址策略（含 DialControl 反 DNS 重绑定）
internal/webvpn/portal.go   门户页
internal/webvpn/assets/     门户模板与运行期 shim.js
internal/auth/store.go      策略持久化与通配符匹配
internal/auth/manager.go    验证码、会话、登录与管理接口
internal/auth/mailer.go     SMTP / 控制台投递
internal/auth/assets/       登录页与管理后台模板
```

## 测试

```bash
go test ./...
go test ./internal/webvpn -bench BenchmarkHTMLRewrite -run '^$'
```

覆盖：三种 codec 的往返、HTML/CSS/srcset 改写与原样透传、`<base>` 语义、SSRF 判定、
端到端代理（含 gzip、跳转、Cookie 重定域、Referer/Origin 翻译、会话 Cookie 剥离）、
登录全流程（含错误码、单次使用、限流、越权与跨站 POST 拒绝）。

## 设计参考

功能形态参考了国内高校常见的 WebVPN 门户（协议选择 + 地址栏 + 资源导航 + 最近访问），
URL 编码形态参考了两种常见方案：路径内嵌加密主机名，以及把主机名编码进泛域名标签
（`.` → `-`，`-` → `--`，https 追加 `-s`）。界面为本项目自行设计，未复制任何产品的视觉。
