# gate_audit · 具备流量审计的企业正向代理服务器

《网络工程项目实施》题目四的实现。一个**域名级访问控制 + 全量审计**的显式正向代理：
客户端把网关当代理，网关按黑/白名单放行或拦截，并把每一次访问记入审计库。

技术要点（也是本项目的三个核心设计）：

1. **转发前判定、转发后异步存储**——判定必须在转发链路上同步完成（快路径），
   落库是磁盘 IO，被挪到转发之后由后台协程异步做（慢路径），两者解耦。
2. **只做域名级审计，不做 MITM**——HTTP 按明文请求行取域名；HTTPS 只根据 CONNECT 的
   域名决定放行与否，隧道内是加密字节流的原样对拷，不解密内容。
3. **两级角色权限**——规则可标注只对 `user` 生效，`admin` 不受其约束。

---

## 一、快速开始

环境：Python 3.12 + [uv](https://docs.astral.sh/uv/)。

```bash
cd gate_audit

uv sync                      # 安装依赖（Flask + pytest）
uv run python -m proxy.main  # 启动（务必在 gate_audit 目录下执行）
```

启动后会看到：

```
[gate_audit] 代理监听      : ('127.0.0.1', 8080)
[gate_audit] 管理端        : http://127.0.0.1:5000
```

### 试用

```bash
# 明文 HTTP 走代理（放行）
curl -x http://127.0.0.1:8080 http://example.com

# 命中黑名单 -> 403
curl -i -x http://127.0.0.1:8080 http://evil.com

# HTTPS（走 CONNECT 隧道，只看域名）
curl -x http://127.0.0.1:8080 https://www.example.com

# 带角色认证（admin 不受只针对 user 的规则约束）
curl -x http://127.0.0.1:8080 -U admin:admin123 http://evil.com
```

浏览器里把 HTTP 代理设为 `127.0.0.1:8080` 即可；管理端在 <http://127.0.0.1:5000>。

### 跑测试

```bash
uv run pytest -q
```

---

## 二、整体架构与数据流

```
                        ┌──────────── 管理端（Flask，守护线程，:5000）────────────┐
                        │  改规则 -> engine.reload() 热更新 + 写回 config.json    │
                        │  查日志 <- storage.query()                              │
                        └──────────────▲──────────────────────▲──────────────────┘
                                       │ 共享同一份对象（有锁保护）
   客户端                              │                      │
     │ TCP 连到 8080                   │                      │
     ▼                                 │                      │
┌──────────────────────────────────────┴──────────────────────┴──────────────┐
│ proxy.connection  读首部 -> 认证(角色) -> 按方法分派                          │
│      │                                                                     │
│      ├─ CONNECT ──> proxy.connect   ┐                                      │
│      └─ 其他     ──> proxy.forward  ┤                                      │
│                                     ├─ 快路径：engine.evaluate() 转发前同步判定 │
│                                     │     命中拦截 -> 403                    │
│                                     └─ 放行 -> 连上游 -> 双向搬运              │
│                                            │                               │
│                                            └─ 慢路径：logger.log() 异步入队   │
└────────────────────────────────────────────────────────────────────────────┘
                                             │
                              asyncio.Queue ─┴─> AuditLogger.run()
                                                     │ run_in_executor
                                                     ▼
                                            AuditStorage（sqlite: audit.db）
```

### 判定优先级

`白名单(放行)` → `黑名单(拦截)` → `网站类型(拦截)` → `正则(拦截)` → `默认策略`

白名单优先级最高，用于给特定站点开绿灯（例如办公必需站点，即使被其他规则覆盖）。

---

## 三、目录与模块职责

| 路径 | 职责 |
| --- | --- |
| `config/config.json` | 全部配置：监听地址、账号、过滤规则 |
| `config/loader.py` | 读配置、只回写 `rules` 字段（不碰运行参数） |
| `filter/rules.py` | 规则数据模型 + 域名匹配（通配、子域） |
| `filter/classifier.py` | 网站粗分类（后缀 + 关键词） |
| `filter/engine.py` | 判定核心：**同步、无 IO**，被转发链路内联调用 |
| `audit/storage.py` | sqlite 薄封装（线程安全） |
| `audit/logger.py` | `asyncio.Queue` 缓冲 + 后台协程异步落库 |
| `auth/roles.py` | `Proxy-Authorization: Basic` 解析、两级角色 |
| `auth/admin_web.py` | Flask 管理端：规则增删 + 审计查询 |
| `proxy/httpmsg.py` | HTTP 首部解析、chunked/Content-Length 消息体搬运 |
| `proxy/forward.py` | HTTP 转发（含判定、审计） |
| `proxy/connect.py` | HTTPS CONNECT 隧道（域名级判定 + 字节对拷） |
| `proxy/connection.py` | 每连接分派、认证、错误隔离 |
| `proxy/main.py` | 装配与启动 |

阅读顺序建议：`proxy/main.py` → `proxy/connection.py` → `proxy/forward.py` → `proxy/connect.py`。

---

## 四、关键实现细节（容易踩坑的点）

**1. 首部结束标志与大小写。** 首部以 `\r\n\r\n` 结束，用 `reader.readuntil(b"\r\n\r\n")` 一次读到位；
字段名大小写不敏感，所以 `proxy.httpmsg.Headers` 统一按小写比较。

**2. 两种请求行格式。** 客户端把代理当代理用时发的是 absolute-form
（`GET http://host/path HTTP/1.1`），转发给源站前必须改回 origin-form
（`GET /path HTTP/1.1`），否则源站不认。

**3. 逐跳首部必须删除。** `Connection`、`Proxy-Connection`、`Keep-Alive`、
`Proxy-Authorization` 等只描述"相邻两跳"，转发时必须吞掉，否则会把客户端的连接语义
泄漏给源站，也会把代理的认证凭据暴露出去。

**4. 消息体长度怎么确定。** `Transfer-Encoding: chunked` → 逐块搬直到 0 块；
`Content-Length: N` → 精确搬 N 字节；都没有 → 请求无 body；响应则读到上游关闭为止。
本项目统一发 `Connection: close`，省掉长连接复用，也让"读到 EOF"成为安全策略。

**5. 子域也算命中。** 规则 `evil.com` 同时命中 `a.evil.com`，否则改个前缀就能绕过。

**6. CONNECT 隧道的边界。** 隧道建立后，代理看不到里面的 URL 与内容——
这是"不解密"方案的固有限制，不是 bug。

**7. 快慢路径分离。** `filter/engine.py` 刻意不 import 任何 IO 模块，
就是为了让它天然适合内联在转发的关键路径上；审计落库全部走队列。

---

## 五、已知限制

- 只做域名级过滤，不做内容/URL 路径级过滤（需 MITM，本项目明确排除）。
- 每个请求强制 `Connection: close`，不做长连接与连接池复用（教学取舍）。
- 无磁盘缓存、无带宽限速、无防病毒扫描。
- 管理端无登录鉴权，且用的是 Flask 开发服务器，仅限演示。
- `config.json` 中的密码为明文，演示用。

---

## 六、测试覆盖

| 测试文件 | 覆盖内容 |
| --- | --- |
| `tests/test_engine.py` | 域名匹配、通配、优先级、分类、正则、角色范围、热更新 |
| `tests/test_roles.py` | Basic 认证的四种分支 |
| `tests/test_proxy_integration.py` | 端到端：放行、拦截、CONNECT 隧道、审计落库、角色权限 |
| `tests/test_admin.py` | 管理端渲染 + 加/删规则热更新 + 持久化 |

集成测试在 `127.0.0.1` 上自建源站与代理（端口取 0 由系统分配），**不依赖外网**。
