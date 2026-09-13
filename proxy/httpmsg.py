"""HTTP 报文处理工具：读首部、解析首部、搬运消息体。

这个模块是整个代理"懂 HTTP"的地方，也是最值得细看的部分。要点：

1) 首部结束标志
   HTTP 首部（请求行/状态行 + 若干首部字段）以"一个空行"结束，即字节序列
   b"\\r\\n\\r\\n"。所以我们用 reader.readuntil(b"\\r\\n\\r\\n") 一次读到位。

2) 首部名字大小写不敏感
   HTTP/1.1 规定首部字段名不区分大小写（Host 与 host 等价）。所以下面用一个
   自制的 Headers 容器统一按小写比较。标准库其实有 email.parser，但那是解析邮件
   用的，对本项目显得过重；自己写十几行反而更直观。

3) "消息体有多长"决定了怎么搬运
   这是最容易写错的地方，规则按优先级：
     - Transfer-Encoding: chunked -> 分块编码，逐块搬，直到 0 块；
     - Content-Length: N          -> 精确搬 N 字节；
     - 以上都没有                 -> 没有 body（但"响应"可能是"读到对端关闭为止"）。

4) 逐跳首部（hop-by-hop）
   Connection / Proxy-Connection / Keep-Alive 这类头只描述"相邻两跳"的连接行为，
   代理转发时必须把它们吞掉，不能原样传给上游——否则会把客户端的连接意愿
   错误地传达给源服务器。这是代理实现里必须处理的一个细节。
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

# 首部最大字节数：防止恶意客户端发一个超大首部把内存打爆
MAX_HEADER_BYTES = 64 * 1024
# 单次读取的块大小
CHUNK_SIZE = 64 * 1024

# 逐跳首部集合：转发前统一删除
HOP_BY_HOP = {
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
}


class Headers:
    """一个极简的"大小写不敏感"首部容器（保持原始顺序）。"""

    def __init__(self, items=None):
        self._items: list[tuple[str, str]] = list(items or [])

    def get(self, name: str, default=None):
        target = name.lower()
        for key, value in self._items:
            if key.lower() == target:
                return value
        return default

    def remove(self, name: str) -> None:
        target = name.lower()
        self._items = [(k, v) for k, v in self._items if k.lower() != target]

    def set(self, name: str, value: str) -> None:
        """设置首部：先删同名（保证只留一个），再追加。"""
        self.remove(name)
        self._items.append((name, value))

    def items(self) -> list[tuple[str, str]]:
        return list(self._items)

    def to_bytes(self) -> bytes:
        """序列化成线上的字节（每行以 CRLF 结束，不含最后的空行）。"""
        return b"".join(f"{k}: {v}\r\n".encode("latin-1") for k, v in self._items)


@dataclass
class RequestHead:
    """一次请求的首行信息。

    代理里会出现两种"请求行"格式，务必区分：
    - absolute-form：GET http://www.example.com/index.html HTTP/1.1
      客户端明确把代理当代理用时，target 是完整 URL。
    - origin-form  ：GET /index.html HTTP/1.1  （配合 Host 头）
      只有直连源站时才会这样；少数客户端/透明代理场景下代理也会遇到。
    """

    method: str          # GET / POST / CONNECT ...
    target: str          # 完整 URL 或路径（见上面的说明）
    version: str         # HTTP/1.1
    headers: Headers
    raw_line: str = ""   # 原始请求行，留着方便排查


async def read_message_head(reader) -> tuple[str, Headers] | None:
    """读取一段首部，返回 (起始行, 首部集合)；读到 EOF / 超时返回 None。

    这一函数对"请求首部"和"响应首部"都适用，区别只在于起始行的语义
    （请求是 METHOD TARGET VERSION，响应是 VERSION CODE REASON）。
    """
    try:
        raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=60)
    except (
        asyncio.IncompleteReadError,     # 对端提前关闭
        asyncio.LimitOverrunError,       # 首部超过 StreamReader 的 limit
        asyncio.TimeoutError,            # 长时间不发送完整首部
        ConnectionError,                 # 连接被重置
    ):
        return None

    text = raw.decode("latin-1")         # HTTP 首部按字节直译，latin-1 可无损往返
    lines = text[:-4].split("\r\n")      # 去掉末尾的 \r\n\r\n 再按行拆
    if not lines:
        return None

    start_line = lines[0]
    items: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        # 处理"折行"（obsolete line folding）：以空格/Tab 开头的行是上一行的续行。
        # 现代客户端基本不用，但既然要"懂协议"就顺手兼容掉。
        if line[0] in " \t" and items:
            key, value = items[-1]
            items[-1] = (key, value + " " + line.strip())
            continue
        name, _, value = line.partition(":")
        items.append((name.strip(), value.strip()))
    return start_line, Headers(items)


async def read_request_head(reader) -> RequestHead | None:
    """读取并解析"请求"首部。"""
    result = await read_message_head(reader)
    if result is None:
        return None
    start_line, headers = result
    parts = start_line.split(" ")
    if len(parts) < 3:
        return None
    return RequestHead(
        method=parts[0],
        target=parts[1],
        version=parts[2],
        headers=headers,
        raw_line=start_line,
    )


# --------------------------------------------------------------------------- #
# 消息体搬运
# --------------------------------------------------------------------------- #
async def relay_body(reader, writer, headers: Headers, *, until_eof: bool = False) -> None:
    """按首部把"消息体"从 reader 抄到 writer。

    参数 until_eof：当既没有 Content-Length 也没有 chunked 时，
    - 请求方向：正常情况就是没有 body，直接返回；
    - 响应方向：可能是"读到连接关闭为止"（HTTP/1.0 风格），此时传 True。
    """
    encoding = (headers.get("transfer-encoding") or "").lower()
    if "chunked" in encoding:
        await _relay_chunked(reader, writer)
        return

    length = headers.get("content-length")
    if length is not None:
        try:
            await _relay_n(reader, writer, int(length))
        except ValueError:
            return          # Content-Length 非法，按无 body 处理
        return

    if until_eof:
        await pump(reader, writer)


async def _relay_n(reader, writer, n: int) -> None:
    """精确搬运 n 字节。"""
    remaining = n
    while remaining > 0:
        chunk = await reader.read(min(CHUNK_SIZE, remaining))
        if not chunk:
            break                       # 上游提前关闭，只能到此为止
        writer.write(chunk)
        remaining -= len(chunk)
    await writer.drain()


async def _relay_chunked(reader, writer) -> None:
    """搬运 chunked 编码的 body。

    分块格式：<十六进制长度>CRLF<数据>CRLF ... 0CRLF [trailer] CRLF
    这里"原样搬运"，不做解码——因为我们只是中转，上游照样能读懂 chunked。
    """
    while True:
        size_line = await reader.readline()
        if not size_line:
            break
        writer.write(size_line)
        try:
            # 形如 "1a;ext=xx\r\n"，取分号前的十六进制数
            size = int(size_line.split(b";")[0].strip() or b"0", 16)
        except ValueError:
            break
        if size == 0:
            # 0 块之后可能有 trailer 首部，直到空行为止
            while True:
                line = await reader.readline()
                writer.write(line)
                if line in (b"\r\n", b"\n", b""):
                    break
            break
        # 数据本身 + 结尾的 CRLF，一并搬运
        data = await reader.readexactly(size + 2)
        writer.write(data)
    await writer.drain()


async def pump(reader, writer) -> None:
    """单向"水管"：把 reader 的数据持续写到 writer，直到 EOF 或出错。

    主要给 CONNECT 隧道用（隧道里跑的是 TLS 等加密字节流，代理不该也无法解析，
    只能老老实实当水管）。
    """
    try:
        while True:
            data = await reader.read(CHUNK_SIZE)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass


# --------------------------------------------------------------------------- #
# 构造响应
# --------------------------------------------------------------------------- #
def text_response(status: str, text: str, extra_headers=None) -> bytes:
    """构造一个简单的纯文本响应（用于 403 拦截提示 / 502 错误提示）。

    status 形如 "403 Forbidden"。
    """
    body = text.encode("utf-8")
    lines = [
        f"HTTP/1.1 {status}",
        "Content-Type: text/plain; charset=utf-8",
        f"Content-Length: {len(body)}",
        "Connection: close",             # 简单起见，回完就关，不用管长连接复用
    ]
    if extra_headers:
        lines.extend(extra_headers)
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    return head + body
