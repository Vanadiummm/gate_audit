# gate_audit · 具备流量审计的企业正向代理服务器

《网络工程项目实施》题目四的实现。一个**域名级访问控制 + 全量审计**的显式正向代理：
客户端把网关当代理，网关按黑/白名单放行或拦截，并把每一次访问记入审计库。

技术要点（也是本项目的四个核心设计）：

1. **转发前判定、转发后异步存储**——判定必须在转发链路上同步完成（快路径），
   落库是磁盘 IO，被挪到转发之后由后台协程异步做（慢路径），两者解耦。
2. **只做域名级审计，不做 MITM**——HTTP 按明文请求行取域名；HTTPS 只根据 CONNECT 的
   域名决定放行与否，隧道内是加密字节流的原样对拷，不解密内容。
3. **代理侧两级角色权限**——规则可标注只对 `user` 生效，`admin` 不受其约束。
4. **管理端两级权限 + 操作留痕**——后台账号与代理账号完全分离；权限以
   「权限点 + 角色矩阵」组织；后台自己的操作也写审计，做到"审计者被审计"。

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

### 管理端默认账号

| 账号 | 密码 | 角色 | 能做什么 |
| --- | --- | --- | --- |
| `root` | `root123` | 超管 superadmin | 看日志、改规则、**管后台账号**、危险操作 |
| `ops` | `ops123` | 管理员 admin | 看日志、改规则 |

> 演示用账号，生产必须改。改密码在管理端「账号管理」页重置即可，
> 也可以直接用模块命令生成哈希后手工填进 `config/config.json`（见 §六）。

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

浏览器里把 HTTP 代理设为 `127.0.0.1:8080` 即可；管理端在 <http://127.0.0.1:5000>
（会先跳到登录页）。

### 跑测试

```bash
uv run pytest -q            # 59 passed
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
| `config/config.json` | 全部配置：监听地址、**后台账号**、代理账号、过滤规则 |
| `config/loader.py` | 读配置、按段回写（`save_rules` / `save_admins` / `save_default_policy`） |
| `filter/rules.py` | 规则数据模型 + 域名匹配（通配、子域） |
| `filter/classifier.py` | 网站粗分类（后缀 + 关键词） |
| `filter/engine.py` | 判定核心：**同步、无 IO**，被转发链路内联调用 |
| `audit/storage.py` | sqlite 薄封装（线程安全）：`audit` + `admin_audit` 两张表 |
| `audit/logger.py` | `asyncio.Queue` 缓冲 + 后台协程异步落库 |
| `auth/roles.py` | 代理端：`Proxy-Authorization: Basic` 解析、两级角色 |
| `auth/admins.py` | **后台端**：角色/权限矩阵、账号存储、scrypt 哈希、失败锁定 |
| `auth/admin_web.py` | Flask 管理端：登录鉴权、权限装饰器、CSRF、规则与账号维护 |
| `auth/templates/` | 管理端 Jinja 模板（`base` / `login` / `index` / `admins`） |
| `proxy/httpmsg.py` | HTTP 首部解析、chunked/Content-Length 消息体搬运 |
| `proxy/forward.py` | HTTP 转发（含判定、审计） |
| `proxy/connect.py` | HTTPS CONNECT 隧道（域名级判定 + 字节对拷） |
| `proxy/connection.py` | 每连接分派、认证、错误隔离 |
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
泄漏给源站，也会把代理的认证凭据暴露出去。

**4. 消息体长度怎么确定。** `Transfer-Encoding: chunked` → 逐块搬直到 0 块；
`Content-Length: N` → 精确搬 N 字节；都没有 → 请求无 body；响应则读到上游关闭为止。
本项目统一发 `Connection: close`，省掉长连接复用，也让"读到 EOF"成为安全策略。

**5. 子域也算命中。** 规则 `evil.com` 同时命中 `a.evil.com`，否则改个前缀就能绕过。

**6. CONNECT 隧道的边界。** 隧道建立后，代理看不到里面的 URL 与内容——
这是"不解密"方案的固有限制，不是 bug。

**7. 快慢路径分离。** `filter/engine.py` 刻意不 import 任何 IO 模块，
就是为了让它天然适合内联在转发的关键路径上；审计落库全部走队列。

**8. 后台为什么用 Session 而不是 Basic。** 代理端用 `Proxy-Authorization` 是协议规定的，
没有替代方案；但后台是网页，Basic 有三个硬伤：无法登出、浏览器反复弹原生框、
不能做会话超时。所以后台走 Flask 的签名 Session Cookie（`itsdangerous` 随 Flask 安装，
没引入新依赖）。

**9. `Perm` 继承 `str` 但 `Enum.__hash__` 按成员名算。**
`hash(Perm.MANAGE_ADMINS)` 实际是 `hash("MANAGE_ADMINS")`，而字符串值是
`"manage_admins"`——所以 `'manage_admins' in frozenset({Perm.MANAGE_ADMINS})`
会返回 **False**。想支持字符串传参（模板里 `can('edit_rules')` 更顺手）就必须
先转成枚举成员再比，不能依赖 `str` 的相等性。`AdminStore.allows()` 里做了这层归一化。

---

## 五、管理端鉴权设计

### 两套身份为什么必须分开

| | 代理账号 `config.users` | 后台账号 `config.admins` |
| --- | --- | --- |
| 身份 | 上网的员工 | 管代理的运维 |
| 数量 | 可能几百个 | 通常个位数 |
| 认证 | `Proxy-Authorization`（Basic） | 表单登录 + Session |
| 存储 | 明文（本轮刻意不动） | 哈希（scrypt） |
| 角色 | `admin` / `user` | `superadmin` / `admin` |

字段语义、存储要求、角色含义全都不同。混在一起会导致"改后台密码误伤上网账号"，
权限泄露面也失控——所以 `config.json` 里是独立的两段。

### 权限矩阵（唯一事实来源）

代码位置：`auth/admins.py` 的 `ROLE_PERMS`。

| 权限点 | 说明 | 超管 | 管理员 |
| --- | --- | :---: | :---: |
| `view_logs` | 查看审计日志 | ✅ | ✅ |
| `edit_rules` | 增删过滤规则 | ✅ | ✅ |
| `manage_admins` | 增删后台账号 / 重置密码 / 改角色 | ✅ | ❌ |
| `dangerous` | 清空访问日志、切换默认策略 | ✅ | ❌ |

路由上只写 `@require(Perm.EDIT_RULES)` 这样的**权限点声明**，不写角色判断。
将来加第三种角色（比如"只读审计员"），只改矩阵一行，不用动任何路由。
模板里同理，用 `{% if can('edit_rules') %}` 控制按钮显隐。

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
| 密码 scrypt 哈希存储，永不回显 | 拖库即得明文 | `auth/admins.py: hash_password` |
| 登录成功后 `session.clear()` | 会话固定攻击 | `login()` |
| `next` 只允许站内相对路径（含排除 `//`） | 开放重定向钓鱼 | `login()` |
| 所有改状态 POST 校验 CSRF token（`compare_digest`） | 借用管理员身份改规则 | `check_csrf()` |
| 登录失败 5 次锁 5 分钟（按 **用户名+IP**） | 暴力破解 / 故意锁死 root | `AdminStore.is_locked` |
| 保护"最后一个超管"（禁删、禁降级） | 后台被永久锁死 | `AdminStore.remove/set_role` |
| 每次请求重新查 `AdminStore` | 被删账号的旧会话立即失效 | `current_admin()` |
| 后台自身操作写 `admin_audit` | 审计者成为审计盲区 | `audit()` + `storage.write_admin` |

关于失败锁定为什么按「用户名 + IP」而不是只按用户名：只按用户名的话，
任何人故意连输 5 次错密码就能把 `root` 锁死——这本身就是一种拒绝服务攻击。
加上 IP 后，锁只影响攻击来源。代价是攻击者换 IP 可以继续尝试；
对教学项目这个权衡是合算的。

### 一个值得注意的设计取舍

`current_admin()` **每次都回查 `AdminStore`**，而不是把角色写进 cookie。
好处是超管删掉某账号后，那个人的旧会话在下一次请求就立即失效，
完全不需要额外的"踢下线"逻辑——因为 `get()` 查不到就返回 `None`，
自然退化成"未登录"。代价是每个请求多一次字典查询（可忽略）。

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

  "admins": {                        // 后台账号：只存哈希，绝不存明文
    "root": { "password_hash": "scrypt:...", "role": "superadmin" },
    "ops":  { "password_hash": "scrypt:...", "role": "admin" }
  },

  "users": {                         // 代理账号（本轮仍为明文，见已知限制）
    "admin": { "password": "admin123", "role": "admin" },
    "alice": { "password": "alice123", "role": "user" }
  },

  "rules": {                         // 过滤规则；管理端改的就是这一段
    "whitelist": ["*.gov.cn", "*.edu.cn"],
    "blacklist": ["evil.com", "gambling.example"],
    "category":  ["gambling"],
    "regex":     [".*\\.bet\\d+\\..*"]
  }
}
```

### 生成密码哈希

```bash
uv run python -m auth.admins <你的密码>
```

**必须用这个命令**，不要手工拼字符串。scrypt 哈希串形如
`scrypt:32768:8:1$<salt>$<hash>`，里面有 `$`；在 PowerShell 里手工拼接时
`$salt` 会被当变量插值成空串，产出一个"看起来正常、但永远校验失败"的错哈希。

### 关于 `admin_secret_key`

`proxy/main.py` 启动时会调 `config.loader.ensure_secret_key()`：
配置里没有就自动生成一个随机值并写回文件。这样保证重启后旧会话仍有效，
也不会把密钥硬编码在源码里。

如果要把本项目提交到公开仓库，建议把 `config/config.json` 加入 `.gitignore`，
只提交一份 `config.example.json`（不含 `admins`、`admin_secret_key`）。

---

## 七、已知限制

- 只做域名级过滤，不做内容/URL 路径级过滤（需 MITM，本项目明确排除）。
- 每个请求强制 `Connection: close`，不做长连接与连接池复用（教学取舍）。
- 无磁盘缓存、无带宽限速、无防病毒扫描。
- **管理端用的是 Flask 开发服务器**，仅限演示，不适合生产（无 TLS、单点、性能低）。
- **代理账号 `users` 的密码仍是明文**——后台账号已改为 scrypt 哈希，
  代理账号属于协议层认证，本轮刻意未动（见 §八）。
- **`SESSION_COOKIE_SECURE` 刻意关闭**：本地是 http，开启后浏览器不回传 cookie，
  会导致"无论如何都登不上"。生产上 HTTPS 后才应打开。

---

## 八、后续改进方向（可写进报告）

1. **代理账号也改哈希**：`users` 段换成 `password_hash`，同步改
   `auth/roles.py` 的校验逻辑。改动面比后台鉴权大（要回归 `test_roles.py`
   与 `test_proxy_integration.py`），所以本轮没有一次做完。
2. **强制代理认证**：目前缺少 `Proxy-Authorization` 时兜底为匿名 `user`，
   不回 `407 Proxy Authentication Required`。要做到"不认证就拒绝"，
   需在 `proxy/connection.py` 加一段判断。
3. **管理端上 HTTPS + 生产级 WSGI 服务器**（waitress / gunicorn）。
4. **跨机部署**：`listen_host` 改 `0.0.0.0` + 放行防火墙 8080；
   管理端保持 `127.0.0.1`，只在本机访问。
5. **长连接与连接池**、内容级过滤、限速与配额。

---

## 九、测试覆盖

| 测试文件 | 用例数 | 覆盖内容 |
| --- | ---: | --- |
| `tests/test_engine.py` | 13 | 域名匹配、通配、优先级、分类、正则、角色范围、热更新 |
| `tests/test_roles.py` | 6 | 代理端 Basic 认证的四种分支 |
| `tests/test_proxy_integration.py` | 8 | 端到端：放行、拦截、CONNECT 隧道、审计落库、角色权限 |
| `tests/test_admin.py` | 10 | 管理端渲染 + 加/删规则热更新 + 持久化 |
| `tests/test_admin_auth.py` | 22 | 未登录跳转、错密、锁定、越权 403、CSRF 400、最后超管保护、密码哈希不回显、登出失效、管理操作落库 |
| **合计** | **59** | |

集成测试在 `127.0.0.1` 上自建源站与代理（端口取 0 由系统分配），**不依赖外网**；
管理端测试用标准库 `urllib` + `CookieJar` 保持登录态，不引入额外测试依赖。

### 说明：`tmp_path_retention_count`

`pyproject.toml` 里把 pytest 的临时目录保留数设成了 1000（实际等于关掉自动清理）。
原因是 pytest 默认会在每次会话开始时删除系统临时目录下较旧的 `pytest-of-*`，
在受限环境下这个跨目录删除会被安全策略拦截。代价是临时目录会留少量残渣（每个几十 KB）。
