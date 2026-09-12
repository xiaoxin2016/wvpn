# 实现与开发

[← 回到 README](../README.md)

## 代码结构

```
.github/workflows/release.yml  打 tag 后交叉编译并发布 Release
cmd/webvpn/main.go          命令行、装配、优雅退出
internal/store/store.go     持久化配置：登录策略、访问策略、书签（管理后台唯一写入点）
internal/webvpn/codec.go    三种 URL 编解码（plain / wrd / subdomain）
internal/webvpn/rewrite.go  HTML / CSS 改写（基于 x/net/html tokenizer，未改动的 token 原样透传）
internal/webvpn/proxy.go    ReverseProxy 装配、请求/响应改写、Cookie 重定域
internal/webvpn/guard.go    目标策略：启动参数硬边界 + 后台站点清单 + 反 DNS 重绑定
internal/webvpn/tls.go      自定义 TLS 拨号：证书验证失败转为询问，确认后按指纹固定信任
internal/webvpn/restore.go  请求参数中的网关地址还原为真实地址（SSO 回跳）
internal/webvpn/pages.go    每个浏览器的访问轨迹，用于判定裸网关地址代表哪个站点
internal/webvpn/cookie.go   Cookie 按原始字节改写（不经 Go 的 cookie 解析/序列化）
internal/webvpn/jar.go      域级 Cookie 的服务端存放，按登录会话隔离
internal/webvpn/portal.go   门户页
internal/webvpn/assets/     门户模板与运行期 shim.js
internal/auth/manager.go    验证码、会话、登录与管理接口
internal/auth/setup.go      首次初始化：一次性令牌、初始化表单与测试发信
internal/auth/mailer.go     SMTP / 控制台投递
internal/auth/assets/       初始化页、登录页与管理后台模板
```

## 构建与发布

```bash
go build -o webvpn ./cmd/webvpn
./webvpn -version          # webvpn dev (commit none, built unknown, go1.24.x)
```

打版本时推一个 `v` 开头的 tag，GitHub Actions（`.github/workflows/release.yml`）会跑
`go vet` 与全量测试，再交叉编译 linux/darwin/windows 各架构的静态二进制并发布 Release：

```bash
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

产物为 `webvpn_<tag>_<os>_<arch>.tar.gz`（Windows 为 `.zip`）以及 `SHA256SUMS`，
版本号、commit 与构建时间通过 `-ldflags` 注入，可用 `-version` 查看。
也可以在 Actions 页面手动触发该工作流：填入版本号，若该 tag 尚不存在，工作流会在指定分支
（默认 `main`）上创建并推送它，再继续构建发布——不需要在本地推 tag。已存在的 tag 则直接补发。

## 测试

```bash
go test ./...
go test ./internal/webvpn -bench BenchmarkHTMLRewrite -run '^$'
```

覆盖：三种 codec 的往返、HTML/CSS/srcset 改写与原样透传、`<base>` 语义、SSRF 判定、
SMTP 配置（校验、密码不回显、留空沿用、显式清除、测试邮件仅发给管理员本人）、
自签名证书流程（询问页、指纹固定、伪造确认被拒、子资源不渲染询问页、返回地址校验）、
Cookie 原始字节保全（非 ASCII / 空格 / 逗号 / 引号值）、域级 Cookie 的服务端回放与会话隔离、
脚本内绝对地址改写（同域命中、他域不动、JSON 转义斜杠、端口、内联脚本不被破坏）、
网关地址配置（模式校验、子域名模式必填泛域名、门户主机须在泛域名内、门户不进目标空间、
端口编码进标签并可往返、超长标签回退路径形式、运行期切换模式即时生效、身份路由只属于门户主机）、
TLS 证书（证书私钥成对校验、私钥不回显、留空沿用、显式清除、证书信息解析）、
SMTP 传输组合（25 端口无认证、明文认证默认拒绝且提示开关、AUTH LOGIN、CRAM-MD5 优先、必须加密）、
反向代理下的客户端 IP 识别（环回对端读 X-Real-IP，远端客户端无法伪造）、
访问策略（黑白名单在主机名与解析地址两个阶段的判定）、端到端代理（含 gzip、跳转、
Cookie 重定域、Referer/Origin 翻译、会话 Cookie 剥离、站点清单拦截）、
登录全流程（含错误码、单次使用、限流、越权与跨站 POST 拒绝）、
登录页不泄露产品名与默认域、配置持久化与校验。

## 设计参考

功能形态参考了国内高校常见的 WebVPN 门户（协议选择 + 地址栏 + 资源导航 + 最近访问），
URL 编码形态参考了两种常见方案：路径内嵌加密主机名，以及把主机名编码进泛域名标签
（`.` → `-`，`-` → `--`，https 追加 `-s`）。界面为本项目自行设计，未复制任何产品的视觉。
