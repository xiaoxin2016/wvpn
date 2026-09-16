# WebVPN

一个用 Go 实现的 WebVPN 网关：浏览器用邮箱验证码登录后，在门户里输入任意 http/https 地址，
由网关代为访问并改写响应，使整个站点后续的请求都回流到网关。本质上是一个**按目标动态路由的
反向代理 + 内容改写器**，客户端不需要装任何东西。

```
浏览器 ──TLS──> WebVPN 网关 ──> 目标站点 (http/https/ws/wss)
          登录态          URL 编解码 + HTML/CSS 改写 + 运行期 JS 补丁
```

单个静态二进制，无外部依赖，配置存一个 JSON 文件；登录策略、访问策略、书签、SMTP、网关地址
与证书都在管理后台里改，**立即生效、无需重启**。

- 邮箱验证码登录，可配默认域；首次启动打印一次性初始化链接，在浏览器里建第一个管理员。
- 三种 URL 编码模式：路径 / 加密路径 / 子域名，后台随时切换。
- 单点登录可用：域级 Cookie 服务端存放按域回放，`redirect_uri` 等回跳地址进出双向还原。
- SSRF 防护：拒绝环回与内网地址，并在拨号时对**实际解析结果**再校验一次，DNS 重绑定同样拦下。
- 目标站点自签名证书由用户确认，确认后按指纹固定信任。
- 会话默认 1 小时未使用即失效，页面自动续期；来源 IP 是否透传给目标站点可在后台开关。

## 部署

### 1. 取二进制

从 [Releases](https://github.com/xiaoxin2016/wvpn/releases) 下载对应平台的压缩包（附 `SHA256SUMS`），或自行构建：

```bash
go build -o webvpn ./cmd/webvpn
```

### 2. 起进程

TLS 建议交给前置 nginx，网关自己监听明文回环地址：

```bash
./webvpn -addr 127.0.0.1:8080 -config /var/lib/webvpn/config.json
```

首次启动没有配置文件时，日志里打印一次性初始化链接：

```
  首次启动：尚未配置管理员
  请在浏览器中打开以下链接完成初始化：

    http://127.0.0.1:8080/setup?token=XA67MT-32EXY6-S5HA24-6D62FS

  该令牌仅在本次进程内有效，管理员首次登录成功后即失效。
```

打开它，填写管理员邮箱与 SMTP（可先「发送测试邮件」验证），完成后即可用验证码登录，
其余配置都在 `/admin` 里改。

### 3. 前置 nginx

```nginx
server {
    listen 443 ssl;
    server_name app.intra.corp.com *.intra.corp.com;   # 子域名模式需要泛域名证书

    ssl_certificate     /etc/ssl/intra.corp.com.crt;
    ssl_certificate_key /etc/ssl/intra.corp.com.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;        # 子域名模式必须保留原始 Host
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;      # 决定网关写出的地址用 http 还是 https
        proxy_set_header Upgrade           $http_upgrade;  # WebSocket
        proxy_set_header Connection        "upgrade";
        proxy_buffering off;                               # SSE
    }
}
```

三个头都别漏：`Host` 决定子域名模式能否解出目标，`X-Forwarded-Proto` 决定写出的地址用什么协议
（漏了会出现混合内容与跨源预检，也可在后台「对外协议」里强制 HTTPS），`X-Real-IP` 决定会话列表
里看到的是真实来源还是 `127.0.0.1`。

### 4. 选域名

网关的泛域名（如 `*.wp.corp.com`）**可以**和被代理站点同处一个注册域——机构通常也只有一个。
浏览器会把该域下的 Cookie 一并发给网关主机，网关会自己划清边界：写进浏览器的 Cookie 带命名空间
前缀，没有前缀的一律不转发给目标站点。详见
[站点兼容性](docs/compatibility.md#cookie-命名空间网关自己划清边界)。

只需确保这个泛域名**由网关独占**，没有别的系统在用它的子域。

### 5. 选 URL 模式

默认是路径模式，单域名即可跑。若站点在网关下行为异常（资源 404、登录态丢失、地址被拼错），
优先改用**子域名模式**——每个目标有独立的浏览器源，兼容性显著更好，代价是需要一条泛域名 DNS
与一张泛域名证书。详见 [URL 模式](docs/url-modes.md)。

### 6. 本地试跑

```bash
./webvpn -addr 127.0.0.1:8080 -allow-private -ignore-email \
  -default-domain test.com -allow-user '*@test.com' -admin 'root@test.com'
```

`-ignore-email` 把验证码打印到控制台，`-allow-private` 允许访问内网地址（生产默认拒绝）。

## 文档

| | |
| --- | --- |
| [配置](docs/configuration.md) | 命令行参数、初始化、邮件发送、访问策略、登录与权限 |
| [URL 模式](docs/url-modes.md) | 路径 / 加密路径 / 子域名三种形态，泛域名与前置代理 |
| [站点兼容性](docs/compatibility.md) | Cookie 与单点登录、回跳地址还原、运行期改写、自签名证书 |
| [安全须知](docs/security.md) | 部署前请读完 |
| [实现与开发](docs/internals.md) | 代码结构、构建发布、测试 |

## 界面

首次启动的初始化页面：创建第一个管理员并配置发信服务。

![初始化](docs/screenshots/setup.png)

登录页只有一个邮箱输入框：既不出现产品名称，也不出现默认邮箱域，
对未认证访问者不暴露任何组织信息。

<p align="center">
  <img src="docs/screenshots/login.png" alt="登录页" width="330">
  <img src="docs/screenshots/login-code.png" alt="验证码" width="330">
</p>

登录后的门户：协议选择 + 地址栏直达，下面是最近访问（仅存于本地浏览器）与运维配置的常用链接。
地址栏直达与书签都在**新标签页**中打开，门户本身留在原处。

![门户](docs/screenshots/portal.png)

管理后台：网关地址、TLS 证书、登录策略、邮件发送、访问策略、单点登录、门户书签、活动会话。

![管理后台](docs/screenshots/admin.png)

网关地址在后台切换，带实时预览与 DNS 提示；泛域名证书同样在后台配置：

<p align="center">
  <img src="docs/screenshots/gateway.png" alt="网关地址" width="420">
  <img src="docs/screenshots/tls.png" alt="TLS 证书" width="420">
</p>

目标站点证书验证失败时的询问页面：

<p align="center"><img src="docs/screenshots/untrusted.png" alt="证书确认" width="560"></p>
