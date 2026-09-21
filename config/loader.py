"""读、写 config.json。相对路径相对项目根；写盘时只替换指定段。"""

from __future__ import annotations

import json
import secrets
import threading
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "config.json"

# 管理端多线程可能同时改规则和账号。
_write_lock = threading.Lock()


@dataclass
class Config:
    """运行参数。"""

    listen_host: str = "127.0.0.1"
    listen_port: int = 8080
    admin_host: str = "127.0.0.1"
    admin_port: int = 5000
    db_path: str = "audit.db"
    default_policy: str = "allow"
    users: dict = field(default_factory=dict)
    admins: dict = field(default_factory=dict)
    admin_secret_key: str = ""
    admin_session_minutes: int = 30
    rules: dict = field(default_factory=dict)
    path: Path = DEFAULT_CONFIG_PATH
    keepalive: bool = True
    pool_max_per_host: int = 8
    pool_idle_seconds: float = 30.0
    limits: dict = field(default_factory=dict)

    def resolve_db_path(self) -> Path:
        """把 db_path 解析成绝对路径。"""
        p = Path(self.db_path)
        return p if p.is_absolute() else (PROJECT_ROOT / p)


def load_config(path: str | Path | None = None) -> Config:
    """读 JSON。文件不存在则用默认值。"""
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
        keepalive=data.get("keepalive", True),
        pool_max_per_host=int(data.get("pool_max_per_host", 8)),
        pool_idle_seconds=float(data.get("pool_idle_seconds", 30.0)),
        limits=data.get("limits", {}),
    )


def _write_section(cfg: Config, key: str, value) -> None:
    """替换 JSON 里的一个 key，其余字段原样写回。"""
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
    _write_section(cfg, "rules", rules)
    cfg.rules = rules


def save_admins(cfg: Config, admins: dict) -> None:
    _write_section(cfg, "admins", admins)
    cfg.admins = admins


def save_default_policy(cfg: Config, policy: str) -> None:
    _write_section(cfg, "default_policy", policy)
    cfg.default_policy = policy


def ensure_secret_key(cfg: Config) -> str:
    """没有 session 密钥就生成并写回。"""
    if cfg.admin_secret_key:
        return cfg.admin_secret_key
    cfg.admin_secret_key = secrets.token_hex(32)
    _write_section(cfg, "admin_secret_key", cfg.admin_secret_key)
    return cfg.admin_secret_key
