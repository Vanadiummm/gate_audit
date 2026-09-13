"""配置加载与回写。

设计说明：
- 配置用 JSON 而不是 YAML。原因：本项目核心要求"尽量纯标准库"，而 Python 标准库
  没有 YAML 解析器（有 json / tomllib / configparser）。JSON 通用、好读，且方便
  管理端把改动回写。
- 一个配置文件同时承载三类内容：
    * 运行参数（监听地址/端口、数据库路径、默认策略）——只在启动时读一次；
    * 客户端账号（用户名/密码/角色）；
    * 过滤规则（黑白名单/类型/正则）——管理端增删后会调用 save_rules() 回写磁盘。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

# 本文件位于 <项目根>/config/loader.py，上两级即项目根目录
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "config.json"


@dataclass
class Config:
    """运行期配置的强类型视图（默认值即"最宽松"配置，方便无配置直接启动）。"""

    listen_host: str = "127.0.0.1"
    listen_port: int = 8080
    admin_host: str = "127.0.0.1"
    admin_port: int = 5000
    db_path: str = "audit.db"
    default_policy: str = "allow"                 # 未命中任何规则时的默认动作
    users: dict = field(default_factory=dict)     # {用户名: {"password":..., "role":...}}
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
        rules=data.get("rules", {}),
        path=cfg_path,
    )


def save_rules(cfg: Config, rules: dict) -> None:
    """把最新规则写回配置文件（管理端改动规则后调用）。

    只覆盖 rules 字段，其余运行参数原样保留，避免把端口等设置改坏。
    """
    if cfg.path.exists():
        data = json.loads(cfg.path.read_text(encoding="utf-8"))
    else:
        data = {}
    data["rules"] = rules
    cfg.path.parent.mkdir(parents=True, exist_ok=True)
    cfg.path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    cfg.rules = rules
