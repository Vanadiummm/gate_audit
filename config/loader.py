"""配置加载与回写。

设计说明：
- 配置用 JSON 而不是 YAML。原因：本项目核心要求"尽量纯标准库"，而 Python 标准库
  没有 YAML 解析器（有 json / tomllib / configparser）。JSON 通用、好读，且方便
  管理端把改动回写。
- 一个配置文件同时承载四类内容：
    * 运行参数（监听地址/端口、数据库路径、默认策略）——只在启动时读一次；
    * 客户端账号 users（用户名/密码/角色）——代理端 Basic 认证用；
    * 后台账号 admins（用户名/密码哈希/角色）——管理端登录用，与 users 是两套身份；
    * 过滤规则（黑白名单/类型/正则）——管理端增删后会调用 save_rules() 回写磁盘。

写盘策略：一律"读回整个 JSON -> 只替换其中一段 -> 整体写回"，
这样改规则不会顺手把端口号改坏，也不会把后台账号段弄丢。
"""

from __future__ import annotations

import json
import secrets
import threading
from dataclasses import dataclass, field
from pathlib import Path

# 本文件位于 <项目根>/config/loader.py，上两级即项目根目录
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "config.json"

# 写配置文件的互斥锁。
# 为什么需要它：save_rules（管理端改规则）与 save_admins（管理端改后台账号）
# 都是"读回 -> 改一段 -> 写回"。管理端是 Flask 多线程服务器，两个请求可能同时进来，
# 若不加锁会出现：A 读、B 读、A 写回、B 写回 —— B 把 A 的改动覆盖掉（丢更新）。
# 注意这是"进程内"的锁，够用，因为本项目只有这一个进程会写这个文件。
_write_lock = threading.Lock()


@dataclass
class Config:
    """运行期配置的强类型视图（默认值即"最宽松"配置，方便无配置直接启动）。"""

    listen_host: str = "127.0.0.1"
    listen_port: int = 8080
    admin_host: str = "127.0.0.1"
    admin_port: int = 5000
    db_path: str = "audit.db"
    default_policy: str = "allow"                 # 未命中任何规则时的默认动作
    users: dict = field(default_factory=dict)     # 代理账号 {用户名: {"password":..., "role":...}}
    admins: dict = field(default_factory=dict)    # 后台账号 {用户名: {"password_hash":..., "role":...}}
    admin_secret_key: str = ""                    # Flask session 的签名密钥（首次启动自动生成并回写）
    admin_session_minutes: int = 30               # 后台登录态超时（分钟）
    rules: dict = field(default_factory=dict)     # {"whitelist":[...], "blacklist":[...], ...}
    path: Path = DEFAULT_CONFIG_PATH              # 记住来源路径，便于回写

    def resolve_db_path(self) -> Path:
        """把 db_path 解析成绝对路径：相对路径相对于项目根目录。"""
        p = Path(self.db_path)
        return p if p.is_absolute() else (PROJECT_ROOT / p)


def load_config(path: str | Path | None = None) -> Config:
    """从 JSON 读取配置。文件不存在时退回内置默认值（规则为空 = 全部放行）。"""
    cfg_path = Path(path) if path else DEFAULT_CONFIG_PATH
    if not cfg_path.exists():
        return Config(path=cfg_path)

    data = json.loads(cfg_path.read_text(encoding="utf-8"))
    return Config(
        listen_host=data.get("listen_host", "127.0.0.1"),
        listen_port=int(data.get("listen_port", 8080)),
        admin_host=data.get("admin_host", "127.0.0.1"),
        admin_port=int(data.get("admin_port", 5000)),
        db_path=data.get("db_path", "audit.db"),
        default_policy=data.get("default_policy", "allow"),
        users=data.get("users", {}),
        admins=data.get("admins", {}),
        admin_secret_key=data.get("admin_secret_key", ""),
        admin_session_minutes=int(data.get("admin_session_minutes", 30)),
        rules=data.get("rules", {}),
        path=cfg_path,
    )


def _write_section(cfg: Config, key: str, value) -> None:
    """把配置文件的某一段（key）整体替换为 value，其余段原样保留。

    所有写盘操作都收敛到这里，好处有两个：
    1) "读-改-写"的逻辑只写一遍，不会某个函数忘了保留其它段；
    2) 锁只有一处，不存在某个调用点漏加锁的可能。
    """
    with _write_lock:
        if cfg.path.exists():
            data = json.loads(cfg.path.read_text(encoding="utf-8"))
        else:
            data = {}
        data[key] = value
        cfg.path.parent.mkdir(parents=True, exist_ok=True)
        cfg.path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )


def save_rules(cfg: Config, rules: dict) -> None:
    """把最新规则写回配置文件（管理端改动规则后调用）。

    只覆盖 rules 段，其余段（端口、accounts、后台账号…）原样保留。
    """
    _write_section(cfg, "rules", rules)
    cfg.rules = rules


def save_admins(cfg: Config, admins: dict) -> None:
    """把后台账号表写回配置文件（超管增删账号/重置密码后调用）。

    同样只覆盖 admins 段，不影响 users（代理账号）与 rules。
    """
    _write_section(cfg, "admins", admins)
    cfg.admins = admins


def save_default_policy(cfg: Config, policy: str) -> None:
    """把默认策略写回配置文件（超管切换 default_policy 后调用）。

    默认策略决定"没命中任何规则时放行还是拦截"，是安全底线开关，
    因此把它归到超管专属的"危险操作"里，并且必须落盘（否则重启就还原了）。
    """
    _write_section(cfg, "default_policy", policy)
    cfg.default_policy = policy


def ensure_secret_key(cfg: Config) -> str:
    """确保存在一个 session 签名密钥；缺失就生成一个并写回配置文件。

    为什么要写回文件，而不是每次启动随机生成？
    随机生成的话，每次重启代理都会让所有管理员的登录态失效
    （旧的 session cookie 是用旧密钥签的，对不上）。写回文件后重启仍保持登录。
    """
    if cfg.admin_secret_key:
        return cfg.admin_secret_key
    cfg.admin_secret_key = secrets.token_hex(32)
    _write_section(cfg, "admin_secret_key", cfg.admin_secret_key)
    return cfg.admin_secret_key
