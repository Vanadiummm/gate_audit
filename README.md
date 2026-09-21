# gate_audit · 具备流量审计的企业正向代理服务器

《网络工程项目实施》题目四的实现。一个**域名级访问控制 + 全量审计**的显式正向代理：
客户端把网关当代理，网关按黑/白名单放行或拦截，并把每一次访问记入审计库。

技术要点：

1. **转发前判定、转发后异步落库**
2. **只做域名级审计，HTTPS 不解密**
3. **代理账号两级角色**（规则可只对 `user` 生效）
4. **后台账号与代理账号分开**，操作写 `admin_audit`
5. **必须代理认证（407）**；HTTP keep-alive 与上游连接池；按角色限速/配额（429）

---

## 一、快速开始

环境：Python 3.12 + [uv](https://docs.astral.sh/uv/)。

```bash
cd gate_audit

uv sync                      # 安装依赖（Flask + pytest）
uv run python -m proxy.main  # 启动（项目根目录）
```

启动后会看到：

```
[gate_audit] 代理监听      : ('127.0.0.1', 8080)
[gate_audit] 管理端        : http://127.0.0.1:5000
```

### 管理端默认账号

| 账号 | 密码 | 角色 | 能做什么 |
| --- | --- | --- | --- |
| `root` | `root123` | 超管 superadmin | 看日志、改规则、**管后台账号**、危险操作 |
| `ops` | `ops123` | 管理员 admin | 看日志、改规则 |

> 默认账号，上线前改掉。改密码可在管理端「账号管理」页重置，
> 或用模块命令生成哈希后填进 `config/config.json`（见 §六）。

### 代理默认账号（走 8080，必须带 `-U`）

| 账号 | 密码 | 角色 | 说明 |
| --- | --- | --- | --- |
| `alice` | `alice123` | user | 受全部员工规则与 `limits.user` 约束 |
| `admin` | `admin123` | admin | 不受 `role: user` 的规则约束；默认不限速 |

缺少或错误的 `Proxy-Authorization` 会得到 **407**，浏览器设代理后会弹出账号框。

### 试用

```bash
# 明文 HTTP 走代理（必须带账号，缺了回 407）
curl -x http://127.0.0.1:8080 -U alice:alice123 http://example.com

# 命中黑名单 -> 403
curl -i -x http://127.0.0.1:8080 -U alice:alice123 http://evil.com

# HTTPS（走 CONNECT 隧道，只看域名）
curl -x http://127.0.0.1:8080 -U alice:alice123 https://www.example.com

# 带角色认证（admin 不受只针对 user 的规则约束）
curl -x http://127.0.0.1:8080 -U admin:admin123 http://evil.com
```

浏览器里把 HTTP 代理设为 `127.0.0.1:8080` 即可；管理端在 <http://127.0.0.1:5000>
（会先跳到登录页）。

### 跑测试

```bash
uv run pytest -q            # 77 passed（以你本机输出为准）
```

---

## 二、整体架构与数据流

```
                        ┌──────────── 管理端（Flask，守护线程，:5000）────────────┐
                        │  登录 -> Session Cookie（超管/管理员）                  │
                        │  改规则 -> engine.reload() 热更新 + 写回 config.json    │
                        │  改账号 -> admins.create/remove + 写回 config.json      │
                        │  查日志 <- storage.query() / storage.query_admin()      │
                        └──────────────▲──────────────────────▲──────────────────┘
                                       │ 共享同一份对象（有锁保护）
   客户端                              │                      │
     │ TCP 连到 8080                   │                      │
     ▼                                 │                      │
┌──────────────────────────────────────┴──────────────────────┴──────────────┐
│ proxy.connection  读首部 -> 认证 -> 限速/配额 -> 按方法分派                     │
│      │  认证失败 407；超限 429；HTTP/1.1 可在同一 TCP 上循环多次请求            │
│      ├─ CONNECT ──> proxy.connect   ┐                                      │
│      └─ 其他     ──> proxy.forward  ┤                                      │
│                                     ├─ 快路径：engine.evaluate() 转发前同步判定 │
│                                     │     命中拦截 -> 403                    │
│                                     └─ 放行 -> 连接池取上游 -> 双向搬运         │
│                                            │                               │
│                                            └─ 慢路径：logger.log() 异步入队   │
└────────────────────────────────────────────────────────────────────────────┘
                                             │
                              asyncio.Queue ─┴─> AuditLogger.run()
                                                     │ run_in_executor
                                                     ▼
                                            AuditStorage（sqlite: audit.db）
                                              ├─ audit        网络访问记录
                                              └─ admin_audit  管理操作记录
```

### 判定优先级

`白名单(放行)` → `黑名单(拦截)` → `网站类型(拦截)` → `正则(拦截)` → `默认策略`

白名单优先级最高，用于给特定站点开绿灯（例如办公必需站点，即使被其他规则覆盖）。

---

## 三、目录与模块职责

| 路径 | 职责 |
| --- | --- |
| `config/config.json` | 全部配置：监听地址、后台/代理账号、规则、连接池、限速配额 |
| `config/loader.py` | 读配置、按段回写（`save_rules` / `save_admins` / `save_default_policy`） |
| `filter/rules.py` | 规则数据模型 + 域名匹配（通配、子域） |
| `filter/classifier.py` | 网站粗分类（后缀 + 关键词） |
| `filter/engine.py` | 判定核心：**同步、无 IO**，被转发链路内联调用 |
| `audit/storage.py` | sqlite 薄封装（线程安全）：`audit` + `admin_audit` 两张表 |
| `audit/logger.py` | `asyncio.Queue` 缓冲 + 后台协程异步落库 |
| `auth/roles.py` | 代理端：Basic 解析、scrypt 校验；失败返回 `None`（由连接层回 407） |
| `auth/admins.py` | **后台端**：角色/权限矩阵、账号存储、scrypt 哈希、失败锁定 |
| `auth/admin_web.py` | Flask 管理端：登录鉴权、权限装饰器、CSRF、规则与账号维护 |
| `auth/templates/` | 管理端 Jinja 模板（`base` / `login` / `index` / `admins`） |
| `proxy/httpmsg.py` | HTTP 首部解析、消息体搬运、`wants_keep_alive` |
| `proxy/pool.py` | 上游明文 HTTP 连接池（CONNECT 隧道不入池） |
| `proxy/limits.py` | 按角色的 rps 令牌桶、bps 限速、请求/字节配额 |
| `proxy/forward.py` | HTTP 转发（判定、池化、限速搬运、审计） |
| `proxy/connect.py` | HTTPS CONNECT 隧道（域名级判定 + 字节对拷） |
| `proxy/connection.py` | 每连接分派、强制认证、429、长连接循环、错误隔离 |
| `proxy/main.py` | 装配与启动 |

阅读顺序建议：`proxy/main.py` → `proxy/connection.py` → `proxy/forward.py`
→ `proxy/connect.py`；管理端另起一条线：`auth/admins.py` → `auth/admin_web.py`。

---

## 四、关键实现细节（容易踩坑的点）

**1. 首部结束标志与大小写。** 首部以 `\r\n\r\n` 结束，用 `reader.readuntil(b"\r\n\r\n")` 一次读到位；
字段名大小写不敏感，所以 `proxy.httpmsg.Headers` 统一按小写比较。

**2. 两种请求行格式。** 客户端把代理当代理用时发的是 absolute-form
（`GET http://host/path HTTP/1.1`），转发给源站前必须改回 origin-form
（`GET /path HTTP/1.1`），否则源站不认。

**3. 逐跳首部必须删除。** `Connection`、`Proxy-Connection`、`Keep-Alive`、
`Proxy-Authorization` 等只描述"相邻两跳"，转发时必须吞掉，否则会把客户端的连接语义
泄漏给源站，也会把代理的认证凭据暴露出去。客户端要不要 keep-alive、代理到源站要不要
keep-alive，是**两跳各自判断**的（`wants_keep_alive`），不能把客户端的 `Connection` 原样转给源站。

**4. 消息体长度与长连接。** `Transfer-Encoding: chunked` → 逐块搬直到 0 块；
`Content-Length: N` → 精确搬 N 字节；都没有 → 请求无 body；响应若源站不 keep-alive
则读到上游关闭为止。HTTP/1.1 默认 keep-alive：同一条客户端 TCP 可循环多次请求；
上游空闲连接按 `(host, port)` 进 `UpstreamPool`。CONNECT 是一对一加密水管，**不入池**。

**5. 子域也算命中。** 规则 `evil.com` 同时命中 `a.evil.com`，否则改个前缀就能绕过。

**6. CONNECT 隧道的边界。** 隧道建立后，代理看不到里面的 URL 与内容——
这是"不解密"方案的固有限制，不是 bug。

**7. 快慢路径。** `filter/engine.py` 不 import IO；审计落库走队列。

**8. 后台用 Session。** 代理认证走 `Proxy-Authorization`（协议要求）；后台是网页，
用 Flask 签名 Session Cookie（`itsdangerous` 随 Flask 安装）。Basic 无法登出、
会反复弹原生框、也不好做超时。

**9. `Perm` 继承 `str` 但 `Enum.__hash__` 按成员名算。**
`hash(Perm.MANAGE_ADMINS)` 实际是 `hash("MANAGE_ADMINS")`，而字符串值是
`"manage_admins"`——所以 `'manage_admins' in frozenset({Perm.MANAGE_ADMINS})`
会返回 **False**。模板里 `can('edit_rules')` 要先转成枚举再比，
不能依赖 `str` 的相等性。`AdminStore.allows()` 里做了归一化。

**10. 认证失败回 407。** `RoleManager.authenticate()` 失败返回 `None`，
由 `proxy/connection.py` 回 `407` 并带 `Proxy-Authenticate: Basic`。
密码错与缺头同等对待。

**11. 限速与配额。** `rps` 用令牌桶，不够就 429（不等待，以免堵死事件循环）；
`bps` 在搬字节时 `sleep` 摊平速度；`quota_requests` / `quota_bytes` 按窗口计数。
配置值 **0 表示不限制**。按**角色**分档（`limits.user` / `limits.admin`），
不是按连接。

---

## 五、管理端鉴权设计

### 两套身份

| | 代理账号 `config.users` | 后台账号 `config.admins` |
| --- | --- | --- |
| 身份 | 上网的员工 | 管代理的运维 |
| 数量 | 可能几百个 | 通常个位数 |
| 认证 | `Proxy-Authorization`（Basic） | 表单登录 + Session |
| 存储 | 哈希（scrypt，`password_hash`） | 哈希（scrypt，`password_hash`） |
| 角色 | `admin` / `user` | `superadmin` / `admin` |

`config.json` 里是独立的两段。哈希格式相同，生成都用
`uv run python -m auth.admins <密码>`。

### 权限矩阵（唯一事实来源）

代码位置：`auth/admins.py` 的 `ROLE_PERMS`。

| 权限点 | 说明 | 超管 | 管理员 |
| --- | --- | :---: | :---: |
| `view_logs` | 查看审计日志 | ✅ | ✅ |
| `edit_rules` | 增删过滤规则 | ✅ | ✅ |
| `manage_admins` | 增删后台账号 / 重置密码 / 改角色 | ✅ | ❌ |
| `dangerous` | 清空访问日志、切换默认策略 | ✅ | ❌ |

路由上写 `@require(Perm.EDIT_RULES)`，模板用 `{% if can('edit_rules') %}`。
加角色只改矩阵。

### 路由一览

| 路由 | 方法 | 所需权限 | 作用 |
| --- | --- | --- | --- |
| `/login` | GET/POST | — | 登录页 / 提交登录 |
| `/logout` | POST | 已登录 | 登出（POST 防被 `<img>` 预取） |
| `/` | GET | `view_logs` | 总览：规则 + 访问审计 + 管理操作日志 |
| `/rules/add` | POST | `edit_rules` | 添加规则（热更新 + 落盘） |
| `/rules/remove` | POST | `edit_rules` | 删除规则 |
| `/admins` | GET | `manage_admins` | 账号列表 |
| `/admins/create` | POST | `manage_admins` | 新建账号 |
| `/admins/remove` | POST | `manage_admins` | 删除账号 |
| `/admins/reset` | POST | `manage_admins` | 重置密码 |
| `/admins/role` | POST | `manage_admins` | 修改角色 |
| `/actions/purge-logs` | POST | `dangerous` | 清空网络访问日志 |
| `/actions/policy` | POST | `dangerous` | 切换默认策略 allow/block |

### 安全措施清单

| 措施 | 防的是什么 | 落在哪 |
| --- | --- | --- |
| 后台与代理密码均为 scrypt 哈希，永不回显 | 拖库即得明文 | `hash_password` / `roles.authenticate` |
| 代理缺凭据或校验失败回 407 | 未认证却按匿名 user 上网 | `proxy/connection.py` |
| 登录成功后 `session.clear()` | 会话固定攻击 | `login()` |
| `next` 只允许站内相对路径（含排除 `//`） | 开放重定向钓鱼 | `login()` |
| 所有改状态 POST 校验 CSRF token（`compare_digest`） | 借用管理员身份改规则 | `check_csrf()` |
| 登录失败 5 次锁 5 分钟（按 **用户名+IP**） | 暴力破解 / 故意锁死 root | `AdminStore.is_locked` |
| 保护"最后一个超管"（禁删、禁降级） | 后台被永久锁死 | `AdminStore.remove/set_role` |
| 每次请求重新查 `AdminStore` | 被删账号的旧会话立即失效 | `current_admin()` |
| 后台自身操作写 `admin_audit` | 审计者成为审计盲区 | `audit()` + `storage.write_admin` |

锁定按「用户名 + IP」。`current_admin()` 每次回查账号表，删号后旧 cookie 下一请求失效。

---

## 六、配置说明

`config/config.json` 的完整结构：

```jsonc
{
  "listen_host": "127.0.0.1",        // 代理监听地址。要跨机用改成 "0.0.0.0"
  "listen_port": 8080,
  "admin_host": "127.0.0.1",         // 管理端建议保持回环，别对外开放
  "admin_port": 5000,
  "db_path": "audit.db",
  "default_policy": "allow",         // 未命中任何规则时的动作

  "admin_secret_key": "<32 字节 hex>",  // 签名 session cookie；首次启动自动生成并写回
  "admin_session_minutes": 30,          // 会话超时

  "keepalive": true,                 // 客户端 HTTP/1.1 长连接
  "pool_max_per_host": 8,            // 每个上游 host 最多缓存几条空闲连接
  "pool_idle_seconds": 30,           // 空闲超过该秒数丢掉

  "limits": {                        // 按角色；数值 0 = 不限制
    "user": {
      "rps": 5,                      // 每秒请求数（令牌桶，超了 429）
      "bps": 65536,                  // 带宽（搬字节时 sleep）
      "quota_requests": 10000,       // 窗口内请求次数
      "quota_bytes": 104857600,      // 窗口内字节
      "quota_window": 86400          // 窗口长度（秒），默认一天
    },
    "admin": { "rps": 0, "bps": 0, "quota_requests": 0, "quota_bytes": 0 }
  },

  "admins": {
    "root": { "password_hash": "scrypt:...", "role": "superadmin" },
    "ops":  { "password_hash": "scrypt:...", "role": "admin" }
  },

  "users": {
    "admin": { "password_hash": "scrypt:...", "role": "admin" },
    "alice": { "password_hash": "scrypt:...", "role": "user" }
  },

  "rules": {
    "whitelist": ["*.gov.cn", "*.edu.cn"],
    "blacklist": ["evil.com", "gambling.example"],
    "category":  ["gambling"],
    "regex":     [".*\\.bet\\d+\\..*"]
  }
}
```

> 代理账号字段名必须是 `password_hash`。若 `config.json` 里还写成 `"password": "scrypt:..."`，
> 校验读不到哈希，所有 `-U` 都会 407。

### 生成密码哈希

后台账号和代理账号用同一条命令：

```bash
uv run python -m auth.admins <你的密码>
```

scrypt 哈希串形如 `scrypt:32768:8:1$<salt>$<hash>`，里面有 `$`。
在 PowerShell 里手工拼接时 `$salt` 会被当变量插值成空串，校验会一直失败。

### 关于 `admin_secret_key`

`proxy/main.py` 启动时会调 `config.loader.ensure_secret_key()`：
配置里没有就生成随机值并回写，重启后旧会话仍有效。

提交到公开仓库时把 `config/config.json` 加入 `.gitignore`，
只提交 `config.example.json`（不含 `admins`、`users`、`admin_secret_key`）。

---

## 七、已知限制

- 只做域名级过滤，不做内容/URL 路径级过滤（需 MITM，本项目明确排除）。
- 无磁盘缓存、无防病毒扫描。
- CONNECT 隧道不进入上游连接池（加密流无法按 HTTP 请求复用）。
- Flask 开发服务器只适合本机演示。
- 未开 `SESSION_COOKIE_SECURE`：本地 http 下开启后浏览器不回传 cookie。生产 HTTPS 再开。

---

## 八、还可以做的

- 管理端 HTTPS + waitress / gunicorn
- 跨机：`listen_host` 改 `0.0.0.0`，管理端仍绑 `127.0.0.1`
- 内容级过滤（需要 MITM，本项目不做）

---

## 九、测试覆盖

| 测试文件 | 用例数 | 覆盖内容 |
| --- | ---: | --- |
| `tests/test_engine.py` | 13 | 域名匹配、通配、优先级、分类、正则、角色范围、热更新 |
| `tests/test_roles.py` | 8 | 代理端 Basic：成功、缺头/错密/坏哈希 → None、忽略明文 `password` |
| `tests/test_limits.py` | 7 | rps 令牌桶、配额、按用户/角色隔离、bps sleep |
| `tests/test_pool.py` | 4 | `wants_keep_alive`、连接复用 / 不复用 |
| `tests/test_proxy_integration.py` | 13 | 放行、拦截、CONNECT、审计、角色、407、keep-alive、429 |
| `tests/test_admin.py` | 10 | 管理端渲染 + 加/删规则热更新 + 持久化 |
| `tests/test_admin_auth.py` | 22 | 未登录跳转、错密、锁定、越权 403、CSRF 400、最后超管保护、密码哈希不回显、登出失效、管理操作落库 |
| **合计** | **77** | |

集成测试在 `127.0.0.1` 上自建源站与代理（端口取 0），不依赖外网。
管理端测试用标准库 `urllib` + `CookieJar`。

`pyproject.toml` 把 pytest 临时目录保留数设成 1000，避免默认清理
`pytest-of-*` 时被安全策略拦截。代价是会留少量残渣。
