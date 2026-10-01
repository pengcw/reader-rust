#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
reader-rust 后台管理 CLI
========================
基于 reader-rust (阅读3.0) 后端 HTTP API 的命令行管理工具。
零第三方依赖,仅使用 Python 标准库。

用法示例:
  reader_admin.py login -u guest -p guest123
  reader_admin.py whoami
  reader_admin.py users list
  reader_admin.py sources list
  reader_admin.py sources add ./book_sources.json
  reader_admin.py sources test --keyword "斗破苍穹"
  reader_admin.py raw GET /reader3/health

配置优先级:命令行参数 > 环境变量(READER_URL / READER_TOKEN / READER_SECURE_KEY / READER_USER_NS) > 配置文件(~/.config/reader-rust/admin.json)
"""

import argparse
import getpass
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".config", "reader-rust")
DEFAULT_CONFIG_FILE = os.path.join(CONFIG_DIR, "admin.json")
DEFAULT_URL = "http://localhost:8080"

APP_VERSION = "1.0.0"


def config_file_path():
    """确定配置文件路径:环境变量 READER_CONFIG > 可写的默认位置。

    若用户目录(~/.config)不可写(如只读沙箱),回退到工作目录下
    的 .reader_admin.json,避免登录因无法保存凭据而失败。
    """
    env = os.environ.get("READER_CONFIG")
    if env:
        return env
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        probe = os.path.join(CONFIG_DIR, ".probe")
        with open(probe, "w") as f:
            f.write("")
        os.remove(probe)
        return DEFAULT_CONFIG_FILE
    except OSError:
        return os.path.join(os.getcwd(), ".reader_admin.json")


class AdminError(Exception):
    """CLI 层错误(接口返回失败或参数错误)。"""


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def load_config():
    path = config_file_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def save_config(cfg):
    path = config_file_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return path


def parse_ms(ms):
    """毫秒时间戳 -> 本地时间字符串。"""
    try:
        return datetime.fromtimestamp(ms / 1000.0).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, OSError, ValueError):
        return str(ms)


class Client:
    """封装对后端 HTTP API 的调用。"""

    def __init__(self, base_url, token=None, secure_key=None, user_ns=None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.secure_key = secure_key
        self.user_ns = user_ns

    def request(self, method, path, body=None, query=None, raw=False, timeout=60):
        url = self.base_url + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        headers = {
            "Accept": "application/json",
            "User-Agent": "reader-admin-cli/%s" % APP_VERSION,
        }
        data = None
        if body is not None:
            if isinstance(body, (dict, list)):
                headers["Content-Type"] = "application/json"
                data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            else:
                data = body
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        if self.secure_key:
            headers["X-Secure-Key"] = self.secure_key
        if self.user_ns:
            headers["X-User-NS"] = self.user_ns

        req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = resp.read()
        except urllib.error.HTTPError as e:
            payload = e.read()
            # 尝试解析错误信息,否则抛出带状态码的错误
            try:
                parsed = json.loads(payload.decode("utf-8"))
                msg = parsed.get("errorMsg") or parsed.get("message") or e.reason
            except (json.JSONDecodeError, UnicodeDecodeError):
                msg = "%s %s" % (e.code, e.reason)
            raise AdminError("HTTP %s: %s" % (e.code, msg))
        except urllib.error.URLError as e:
            raise AdminError("无法连接服务器 %s: %s" % (self.base_url, e.reason))
        except OSError as e:
            raise AdminError("网络错误: %s" % e)

        text = payload.decode("utf-8", errors="replace")
        if raw:
            return text
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            return text
        if isinstance(obj, dict) and "isSuccess" in obj and not obj.get("isSuccess"):
            raise AdminError(obj.get("errorMsg") or "接口返回失败")
        return obj

    def get(self, path, query=None, **kw):
        return self.request("GET", path, query=query, **kw)

    def post(self, path, body=None, **kw):
        return self.request("POST", path, body=body, **kw)


def resolve_client(args):
    cfg = load_config()
    url = getattr(args, "url", None) or os.environ.get("READER_URL") or cfg.get("url") or DEFAULT_URL
    token = getattr(args, "token", None) or os.environ.get("READER_TOKEN") or cfg.get("accessToken")
    secure_key = (
        getattr(args, "secure_key", None)
        or os.environ.get("READER_SECURE_KEY")
        or cfg.get("secureKey")
    )
    user_ns = (
        getattr(args, "user_ns", None)
        or os.environ.get("READER_USER_NS")
        or cfg.get("userNS")
    )
    return Client(url, token, secure_key, user_ns)


def need_auth(client):
    if not client.token:
        raise AdminError("未登录,请先执行 login(或使用 --token / READER_TOKEN)")


# ---------- 输出工具 ----------

def print_table(headers, rows, json_mode=False):
    """打印表格;json_mode 下输出原始数据结构。"""
    if json_mode:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return
    if not rows:
        print("(空)")
        return
    width = os.get_terminal_size().columns if sys.stdout.isatty() else 120
    cols = list(headers)
    cells = [[("" if r.get(c) is None else str(r.get(c))) for c in cols] for r in rows]
    col_w = [max(len(cols[i]), *(len(r[i]) for r in cells)) for i in range(len(cols))]
    total = sum(col_w) + 3 * (len(cols) - 1)
    if total > width:
        scale = width / total
        col_w = [max(8, int(w * scale)) for w in col_w]
    fmt = "  ".join("{%d:<%d}" % (i, col_w[i]) for i in range(len(cols)))
    print(fmt.format(*cols))
    print("-" * min(sum(col_w) + 3 * (len(cols) - 1), width))
    for r in cells:
        cells_trunc = [c[:col_w[i]] for i, c in enumerate(r)]
        print(fmt.format(*cells_trunc))


def parse_json_arg(value):
    """--data 支持:JSON 字面量 / @文件路径 / - 表示 stdin。"""
    if value is None:
        return None
    if value == "-":
        return json.load(sys.stdin)
    if value.startswith("@"):
        with open(value[1:], "r", encoding="utf-8") as f:
            return json.load(f)
    return json.loads(value)


# ---------- 认证相关命令 ----------

def cmd_login(args, client):
    username = args.username
    password = args.password
    if not username:
        username = input("用户名: ").strip()
    if not username:
        raise AdminError("用户名不能为空")
    if password is None:
        password = getpass.getpass("密码: ")
    body = {"username": username, "password": password, "isLogin": True}
    data = client.post("/reader3/login", body).get("data", {})
    token = data.get("accessToken")
    if not token:
        raise AdminError("登录成功但未返回 accessToken")
    cfg = load_config()
    cfg["url"] = client.base_url
    cfg["accessToken"] = token
    cfg["username"] = username
    try:
        path = save_config(cfg)
        print("登录成功: %s (isAdmin=%s),凭据已保存到 %s" % (username, data.get("isAdmin"), path))
    except OSError as e:
        print("登录成功: %s (isAdmin=%s)" % (username, data.get("isAdmin")))
        eprint("警告: 无法保存凭据到配置文件(%s),请用 --token 或环境变量 READER_TOKEN 复用" % e)
    print("accessToken: %s" % token)


def cmd_register(args, client):
    username = args.username
    password = args.password
    if not username:
        username = input("用户名: ").strip()
    if not username:
        raise AdminError("用户名不能为空")
    if password is None:
        password = getpass.getpass("密码: ")
    body = {"username": username, "password": password}  # 不传 isLogin => 注册
    data = client.post("/reader3/login", body).get("data", {})
    token = data.get("accessToken")
    cfg = load_config()
    cfg["url"] = client.base_url
    if token:
        cfg["accessToken"] = token
        cfg["username"] = username
        try:
            path = save_config(cfg)
            print("注册成功: %s,凭据已保存到 %s" % (username, path))
        except OSError:
            print("注册成功: %s(警告: 凭据保存失败,请记录下方 token)" % username)
        print("accessToken: %s" % token)
    else:
        print("注册成功: %s" % username)


def cmd_logout(args, client):
    need_auth(client)
    # 先清除本地凭据,再通知服务端(服务端 logout 未开启 secure 时返回"不支持的操作",不阻塞)
    cfg = load_config()
    cfg.pop("accessToken", None)
    try:
        path = save_config(cfg)
        print("已退出登录,本地凭据已清除(%s)" % path)
    except OSError as e:
        eprint("警告: 无法写入配置文件(%s),请手动删除 %s" % (e, config_file_path()))
    try:
        client.post("/reader3/logout", {})
    except AdminError:
        pass
    return 0


def cmd_whoami(args, client):
    need_auth(client)
    data = client.get("/reader3/getUserInfo").get("data", {})
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return
    ui = data.get("userInfo") or {}  # token 失效时服务端返回 null
    if not ui:
        print("未登录或 token 已失效,请重新 login")
        return
    print("用户名:        %s" % ui.get("username"))
    print("管理员:        %s" % ui.get("isAdmin"))
    print("WebDAV:        %s" % ui.get("enableWebdav"))
    print("本地存储:      %s" % ui.get("enableLocalStore"))
    print("AI 模型:       %s" % ui.get("enableAiModel"))
    print("最后登录:      %s" % parse_ms(ui.get("lastLoginAt")))
    print("安全模式:      %s" % data.get("secure"))
    print("需管理密码:    %s" % data.get("secureKeyRequired"))
    print("管理员授权:    %s" % data.get("adminAuthorized"))


# ---------- 用户管理 ----------

def cmd_users_list(args, client):
    need_auth(client)
    data = client.get("/reader3/getUserList").get("data", [])
    if isinstance(data, dict):  # 兼容异常返回
        raise AdminError(json.dumps(data, ensure_ascii=False))
    rows = [
        {
            "username": u.get("username", ""),
            "isAdmin": "是" if u.get("isAdmin") else "否",
            "webdav": "是" if u.get("enableWebdav") else "否",
            "local": "是" if u.get("enableLocalStore") else "否",
            "ai": "是" if u.get("enableAiModel") else "否",
            "createdAt": parse_ms(u.get("createdAt")),
            "lastLoginAt": parse_ms(u.get("lastLoginAt")),
        }
        for u in data
    ]
    print_table(["username", "isAdmin", "webdav", "local", "ai", "createdAt", "lastLoginAt"], rows, args.json)


def cmd_users_add(args, client):
    need_auth(client)
    if args.password is None:
        args.password = getpass.getpass("为新用户设置密码: ")
    data = client.post("/reader3/addUser", {"username": args.username, "password": args.password}).get("data", [])
    print("已创建用户 %s,当前共 %d 个用户" % (args.username, len(data) if isinstance(data, list) else 0))


def cmd_users_delete(args, client):
    need_auth(client)
    users = args.usernames
    if not users and sys.stdin.isatty():
        raise AdminError("请指定要删除的用户名")
    if not users:
        users = [line.strip() for line in sys.stdin if line.strip()]
    data = client.post("/reader3/deleteUsers", users).get("data", [])
    print("已删除 %s,剩余 %d 个用户" % (", ".join(users), len(data) if isinstance(data, list) else 0))


def cmd_users_reset_password(args, client):
    need_auth(client)
    if args.password is None:
        args.password = getpass.getpass("新密码: ")
    client.post("/reader3/resetPassword", {"username": args.username, "password": args.password})
    print("已重置用户 %s 的密码" % args.username)


def cmd_users_update(args, client):
    need_auth(client)
    body = {"username": args.username}
    if args.webdav is not None:
        body["enableWebdav"] = args.webdav
    if args.local_store is not None:
        body["enableLocalStore"] = args.local_store
    if args.ai_model is not None:
        body["enableAiModel"] = args.ai_model
    data = client.post("/reader3/updateUser", body).get("data", [])
    print("已更新用户 %s" % args.username)


def cmd_passwd(args, client):
    need_auth(client)
    old = args.old_password
    new = args.new_password
    if old is None:
        old = getpass.getpass("当前密码: ")
    if new is None:
        new = getpass.getpass("新密码: ")
    client.post("/reader3/changePassword", {"oldPassword": old, "newPassword": new})
    print("密码修改成功")


# ---------- 书源管理 ----------

def cmd_sources_list(args, client):
    need_auth(client)
    data = client.get("/reader3/getBookSources").get("data", [])
    if isinstance(data, dict):
        raise AdminError(json.dumps(data, ensure_ascii=False))
    rows = [
        {
            "enabled": "✓" if s.get("enabled", True) else "✗",
            "bookSourceName": s.get("bookSourceName", ""),
            "bookSourceUrl": s.get("bookSourceUrl", ""),
            "group": s.get("bookSourceGroup", ""),
            "respond": s.get("respondTime", ""),
            "comment": s.get("bookSourceComment", ""),
        }
        for s in data
    ]
    print_table(["enabled", "bookSourceName", "bookSourceUrl", "group", "respond", "comment"], rows, args.json)


def cmd_sources_get(args, client):
    need_auth(client)
    data = client.post("/reader3/getBookSource", {"bookSourceUrl": args.source_url}).get("data", {})
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print("名称:  %s" % data.get("bookSourceName"))
        print("URL:   %s" % data.get("bookSourceUrl"))
        print("分组:  %s" % data.get("bookSourceGroup"))
        print("启用:  %s" % data.get("enabled"))
        print("搜索URL: %s" % data.get("searchUrl"))
        print("评论:  %s" % data.get("bookSourceComment"))


def parse_sources_text(text):
    """解析书源文本:支持数组 JSON、单对象、JSONL(每行一个 JSON 对象)。"""
    text = text.strip()
    if not text:
        raise AdminError("内容为空")
    try:
        obj = json.loads(text)
        if isinstance(obj, list):
            return obj
        return [obj]
    except json.JSONDecodeError:
        pass
    sources = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            raise AdminError("第 %d 行不是合法 JSON: %s" % (len(sources) + 1, e))
        if isinstance(obj, list):
            sources.extend(obj)
        else:
            sources.append(obj)
    if not sources:
        raise AdminError("未解析到任何书源")
    return sources


def cmd_sources_add(args, client):
    need_auth(client)
    if getattr(args, "remote_url", None):  # 远程源文件,由服务端拉取并解析
        resp = client.post("/reader3/readRemoteSourceFile", {"url": args.remote_url}).get("data", [])
        sources = []
        for item in resp:
            if isinstance(item, str):
                sources.extend(parse_sources_text(item))
            elif isinstance(item, list):
                sources.extend(item)
    else:  # 本地文件 / 标准输入
        path = args.path or "-"
        if path == "-":
            text = sys.stdin.read()
        else:
            with open(path, "r", encoding="utf-8") as f:
                text = f.read()
        sources = parse_sources_text(text)
    if not sources:
        raise AdminError("未解析到任何书源")
    result = client.post("/reader3/saveBookSources", sources).get("data", {})
    count = result.get("count", len(sources))
    print("已导入 %d/%d 个书源" % (count, len(sources)))


def cmd_sources_export(args, client):
    need_auth(client)
    data = client.get("/reader3/getBookSources").get("data", [])
    if isinstance(data, dict):
        raise AdminError(json.dumps(data, ensure_ascii=False))
    if args.urls:
        wanted = set(args.urls)
        data = [s for s in data if s.get("bookSourceUrl") in wanted]
    out = json.dumps(data, ensure_ascii=False, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out + "\n")
        print("已导出 %d 个书源到 %s" % (len(data), args.output))
    else:
        print(out)


def cmd_sources_delete(args, client):
    need_auth(client)
    urls = args.urls
    if not urls and not sys.stdin.isatty():
        urls = [line.strip() for line in sys.stdin if line.strip()]
    if not urls:
        raise AdminError("请用 -u/--url 指定要删除的书源 URL(或通过 stdin 传入)")
    result = client.post("/reader3/deleteBookSources", [{"bookSourceUrl": u} for u in urls]).get("data", {})
    print("已删除 %d 个书源: %s" % (len(urls), ", ".join(urls)))


def cmd_sources_delete_all(args, client):
    need_auth(client)
    if not args.yes:
        confirm = input("确认删除所有书源?输入 yes 确认: ").strip()
        if confirm != "yes":
            print("已取消")
            return
    result = client.post("/reader3/deleteAllBookSources", {}).get("data", {})
    print("已删除全部书源")


def cmd_sources_delete_invalid(args, client):
    need_auth(client)
    result = client.post("/reader3/deleteInvalidBookSources", {}).get("data", {})
    deleted = result.get("deleted") if isinstance(result, dict) else None
    if isinstance(deleted, int) and not isinstance(deleted, bool):
        print("已删除 %s 个失效书源" % deleted)
    else:
        print("已删除全部失效书源")


def cmd_sources_test(args, client):
    need_auth(client)
    body = {
        "keyword": args.keyword,
        "markInvalid": args.mark_invalid,
        "concurrent": args.concurrent,
    }
    if args.urls:
        body["bookSourceUrls"] = args.urls
    data = client.post("/reader3/testBookSources", body).get("data", {})
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return
    results = data.get("results", [])
    print("总 %s 个书源: 有效 %s / 无效 %s / 标记失效 %s" % (
        data.get("total"), data.get("valid"), data.get("invalid"), data.get("markedInvalid")))
    rows = [
        {
            "valid": "✓" if r.get("valid") else "✗",
            "bookSourceName": r.get("bookSourceName", ""),
            "bookSourceUrl": r.get("bookSourceUrl", ""),
            "search": "✓" if r.get("searchOk") else ("✗" if r.get("searchError") else "-"),
            "explore": "✓" if r.get("exploreOk") else ("✗" if r.get("exploreError") else "-"),
            "group": r.get("group", ""),
            "error": (r.get("searchError") or r.get("exploreError") or ""),
        }
        for r in results
    ]
    print_table(["valid", "bookSourceName", "bookSourceUrl", "search", "explore", "group", "error"], rows, args.json)


def cmd_sources_set_default(args, client):
    need_auth(client)
    data = client.post("/reader3/setAsDefaultBookSources", {"username": args.username}).get("data", {})
    print("已将默认书源应用到用户 %s (%s 个)" % (args.username, data.get("count", "?")))


# ---------- RSS ----------

def cmd_rss_list(args, client):
    need_auth(client)
    data = client.get("/reader3/getRssSources").get("data", [])
    if isinstance(data, dict):
        raise AdminError(json.dumps(data, ensure_ascii=False))
    rows = [
        {
            "enabled": "✓" if s.get("enabled", True) else "✗",
            "sourceName": s.get("sourceName", ""),
            "sourceUrl": s.get("sourceUrl", ""),
            "group": s.get("sourceGroup", ""),
            "comment": s.get("sourceComment", ""),
        }
        for s in data
    ]
    print_table(["enabled", "sourceName", "sourceUrl", "group", "comment"], rows, args.json)


def cmd_rss_add(args, client):
    need_auth(client)
    if getattr(args, "remote_url", None):
        resp = client.post("/reader3/readRemoteRssSourceFile", {"url": args.remote_url}).get("data", [])
        sources = []
        for item in resp:
            if isinstance(item, str):
                sources.extend(parse_sources_text(item))
            elif isinstance(item, list):
                sources.extend(item)
    else:
        path = args.path or "-"
        if path == "-":
            text = sys.stdin.read()
        else:
            with open(path, "r", encoding="utf-8") as f:
                text = f.read()
        sources = parse_sources_text(text)
    if not sources:
        raise AdminError("未解析到任何 RSS 源")
    result = client.post("/reader3/saveRssSources", sources).get("data", {})
    count = result.get("deleted", len(sources)) if isinstance(result, dict) else len(sources)
    print("已导入 %s 个 RSS 源" % count)


def cmd_rss_delete(args, client):
    need_auth(client)
    urls = args.urls
    if not urls and not sys.stdin.isatty():
        urls = [line.strip() for line in sys.stdin if line.strip()]
    if not urls:
        raise AdminError("请用 -u/--url 指定要删除的 RSS 源 URL")
    result = client.post("/reader3/deleteRssSources", [{"sourceUrl": u} for u in urls]).get("data", {})
    print("已删除 %d 个 RSS 源: %s" % (len(urls), ", ".join(urls)))


# ---------- 书架 ----------

def cmd_shelf_list(args, client):
    need_auth(client)
    data = client.get("/reader3/getBookshelf").get("data", [])
    if isinstance(data, dict):
        raise AdminError(json.dumps(data, ensure_ascii=False))
    rows = [
        {
            "name": b.get("name", ""),
            "author": b.get("author", ""),
            "origin": b.get("originName", "") or b.get("origin", ""),
            "bookUrl": b.get("bookUrl", ""),
            "progress": "%s/%s" % (b.get("durChapterTitle", ""), b.get("totalChapterNum", "")),
            "group": b.get("group", ""),
        }
        for b in data
    ]
    print_table(["name", "author", "origin", "bookUrl", "progress", "group"], rows, args.json)


def cmd_shelf_add(args, client):
    need_auth(client)
    if getattr(args, "data", None):
        payload = parse_json_arg(args.data)
        if isinstance(payload, list):
            # 逐本调用 saveBook(增量合并),避免 saveBooks 整体覆盖书架
            if not payload:
                raise AdminError("书籍列表为空")
            count = 0
            for book in payload:
                if not book.get("bookUrl") or not book.get("origin"):
                    raise AdminError("每本书都需要 bookUrl 和 origin: %s" % book.get("name", "?"))
                client.post("/reader3/saveBook", book)
                count += 1
            print("已成功添加 %d 本书籍到书架(增量合并,不覆盖已有书籍)" % count)
            return
        book = payload
    else:
        if not args.name or not args.book_url or not args.origin:
            raise AdminError("添加书籍需要指定 --name, --book-url, --origin (或使用 --data 传入 JSON)")
        book = {
            "name": args.name,
            "author": args.author or "",
            "bookUrl": args.book_url,
            "origin": args.origin,
        }
        if args.origin_name:
            book["originName"] = args.origin_name
        if args.cover_url:
            book["coverUrl"] = args.cover_url
        if args.intro:
            book["intro"] = args.intro
        if getattr(args, "group", None) is not None:
            book["group"] = args.group

    data = client.post("/reader3/saveBook", book).get("data", {})
    print("成功添加书籍到书架: 《%s》 (%s) [URL: %s]" % (
        data.get("name") or book.get("name"),
        data.get("author") or book.get("author", ""),
        data.get("bookUrl") or book.get("bookUrl"),
    ))


def cmd_shelf_delete(args, client):
    need_auth(client)
    book = {"bookUrl": args.book_url, "name": getattr(args, "name", "") or ""}
    client.post("/reader3/deleteBook", book)
    print("已从书架删除书籍: %s" % args.book_url)


def cmd_shelf_default(args, client):
    if getattr(args, "action", None):
        return
    cmd_shelf_list(args, client)


# ---------- 分组 ----------

def cmd_groups_list(args, client):
    need_auth(client)
    data = client.get("/reader3/getBookGroups").get("data", [])
    if isinstance(data, dict):
        raise AdminError(json.dumps(data, ensure_ascii=False))
    rows = [{"groupId": g.get("groupId"), "groupName": g.get("groupName"), "orderNo": g.get("orderNo")} for g in data]
    print_table(["groupId", "groupName", "orderNo"], rows, args.json)


def cmd_groups_add(args, client):
    need_auth(client)
    data = client.post("/reader3/saveBookGroup", {"groupId": args.id, "groupName": args.name, "orderNo": args.order}).get("data")
    print("已保存分组: %s" % data)


def cmd_groups_delete(args, client):
    need_auth(client)
    client.post("/reader3/deleteBookGroup", {"groupId": args.id})
    print("已删除分组 %s" % args.id)


# ---------- 替换规则 ----------

def cmd_rules_list(args, client):
    need_auth(client)
    data = client.get("/reader3/getReplaceRules").get("data", [])
    if isinstance(data, dict):
        raise AdminError(json.dumps(data, ensure_ascii=False))
    rows = [
        {
            "id": r.get("id"),
            "name": r.get("name", ""),
            "group": r.get("group", ""),
            "pattern": r.get("pattern", ""),
            "enabled": "是" if r.get("isEnabled") else "否",
        }
        for r in data
    ]
    print_table(["id", "name", "group", "pattern", "enabled"], rows, args.json)


def cmd_rules_add(args, client):
    need_auth(client)
    rules = parse_json_arg(args.data)
    if not isinstance(rules, list):
        rules = [rules]
    client.post("/reader3/saveReplaceRules", rules)
    print("已保存 %d 条替换规则" % len(rules))


def cmd_rules_delete(args, client):
    need_auth(client)
    client.post("/reader3/deleteReplaceRule", {"name": args.name})
    print("已删除替换规则: %s" % args.name)


# ---------- 其他 ----------

def cmd_version(args, client):
    need_auth(client)
    data = client.get("/reader3/getVersionUpdate", query={"force": "true" if args.force else "false"}).get("data", {})
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return
    print("当前版本:   %s" % data.get("currentVersion"))
    print("最新版本:   %s" % data.get("latestVersion"))
    print("发布名称:   %s" % data.get("latestName"))
    print("发布时间:   %s" % parse_ms(data.get("publishedAt")))
    print("下载地址:   %s" % data.get("releaseUrl"))
    print("可更新:     %s" % data.get("updateAvailable"))
    print("错误:       %s" % (data.get("error") or "-"))


def cmd_health(args, client):
    resp = client.get("/health", raw=True)
    print(resp)


def cmd_raw(args, client):
    """通用请求:raw <METHOD> <PATH> [--data <json|@file|->] [--query k=v ...]"""
    query = {}
    for kv in args.query or []:
        if "=" not in kv:
            raise AdminError("query 参数格式应为 k=v: %s" % kv)
        k, v = kv.split("=", 1)
        query[k] = v
    body = parse_json_arg(args.data) if args.data is not None else None
    resp = client.request(args.method, args.path, body=body, query=query or None)
    if isinstance(resp, str):
        print(resp)
    else:
        print(json.dumps(resp, ensure_ascii=False, indent=2))


# ---------- argparse ----------

def build_parser():
    # 公共参数:允许 --json 出现在子命令之前或之后
    COMMON = argparse.ArgumentParser(add_help=False)
    COMMON.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="以 JSON 输出结果")

    p = argparse.ArgumentParser(
        prog="reader_admin.py",
        description="reader-rust (阅读3.0) 后台管理命令行工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""示例:
  %(prog)s login -u guest -p guest123
  %(prog)s whoami
  %(prog)s users list
  %(prog)s sources list
  %(prog)s sources add ./book_sources.json
  %(prog)s sources test --keyword "斗破苍穹"
  %(prog)s raw GET /reader3/health

环境变量: READER_URL / READER_TOKEN / READER_SECURE_KEY / READER_USER_NS / READER_CONFIG
凭据保存于: {config_file_path()}（不可写时回退到工作目录 .reader_admin.json）""",
    )
    p.add_argument("--url", help="后端地址(默认 %s)" % DEFAULT_URL)
    p.add_argument("--token", help="accessToken(优先于配置文件)")
    p.add_argument("--secure-key", help="管理密码 (X-Secure-Key)")
    p.add_argument("--user-ns", help="用户命名空间 (X-User-NS)")
    p.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="以 JSON 输出结果")
    sub = p.add_subparsers(dest="command", metavar="命令")

    # 认证
    sp = sub.add_parser("login", parents=[COMMON], help="登录(需已注册账号)")
    sp.add_argument("-u", "--username")
    sp.add_argument("-p", "--password")
    sp.set_defaults(func=cmd_login)

    sp = sub.add_parser("register", parents=[COMMON], help="注册新账号")
    sp.add_argument("-u", "--username")
    sp.add_argument("-p", "--password")
    sp.set_defaults(func=cmd_register)

    sp = sub.add_parser("logout", parents=[COMMON], help="退出登录")
    sp.set_defaults(func=cmd_logout)

    sp = sub.add_parser("whoami", parents=[COMMON], help="查看当前登录用户信息")
    sp.set_defaults(func=cmd_whoami)

    # 用户管理
    sp = sub.add_parser("users", parents=[COMMON], help="用户管理")
    usub = sp.add_subparsers(dest="action", metavar="操作", required=True)

    u = usub.add_parser("list", parents=[COMMON], help="用户列表(需管理员)")
    u.set_defaults(func=cmd_users_list)

    u = usub.add_parser("add", parents=[COMMON], help="添加用户(需管理员)")
    u.add_argument("-u", "--username", required=True)
    u.add_argument("-p", "--password")
    u.set_defaults(func=cmd_users_add)

    u = usub.add_parser("delete", parents=[COMMON], help="删除用户(需管理员)")
    u.add_argument("usernames", nargs="*", help="用户名列表,或用 stdin 逐行传入")
    u.set_defaults(func=cmd_users_delete)

    u = usub.add_parser("reset-password", parents=[COMMON], help="重置指定用户密码(需管理员)")
    u.add_argument("-u", "--username", required=True)
    u.add_argument("-p", "--password")
    u.set_defaults(func=cmd_users_reset_password)

    u = usub.add_parser("update", parents=[COMMON], help="更新用户开关(需管理员)")
    u.add_argument("-u", "--username", required=True)
    u.add_argument("--webdav", type=bool_flag, help="enableWebdav true/false")
    u.add_argument("--local-store", type=bool_flag, help="enableLocalStore true/false")
    u.add_argument("--ai-model", type=bool_flag, help="enableAiModel true/false")
    u.set_defaults(func=cmd_users_update)

    sp = sub.add_parser("passwd", parents=[COMMON], help="修改当前用户密码")
    sp.add_argument("--old-password")
    sp.add_argument("--new-password")
    sp.set_defaults(func=cmd_passwd)

    # 书源
    sp = sub.add_parser("sources", parents=[COMMON], help="书源管理")
    ssub = sp.add_subparsers(dest="action", metavar="操作", required=True)

    s = ssub.add_parser("list", parents=[COMMON], help="书源列表")
    s.set_defaults(func=cmd_sources_list)

    s = ssub.add_parser("get", parents=[COMMON], help="查看单个书源")
    s.add_argument("-u", "--url", dest="source_url", required=True, help="bookSourceUrl")
    s.set_defaults(func=cmd_sources_get)

    s = ssub.add_parser("add", parents=[COMMON], help="导入书源(本地文件/远程URL/标准输入)")
    s.add_argument("path", nargs="?", help="本地文件路径;- 表示 stdin")
    s.add_argument("--remote-url", help="远程书源文件 URL")
    s.set_defaults(func=cmd_sources_add)

    s = ssub.add_parser("export", parents=[COMMON], help="导出书源(JSON)")
    s.add_argument("-o", "--output", help="输出文件(默认 stdout)")
    s.add_argument("-u", "--urls", nargs="*", help="仅导出指定 bookSourceUrl")
    s.set_defaults(func=cmd_sources_export)

    s = ssub.add_parser("delete", parents=[COMMON], help="删除书源")
    s.add_argument("-u", "--urls", nargs="*", help="bookSourceUrl 列表,或用 stdin 逐行传入")
    s.set_defaults(func=cmd_sources_delete)

    s = ssub.add_parser("delete-all", parents=[COMMON], help="删除全部书源")
    s.add_argument("-y", "--yes", action="store_true", help="跳过确认")
    s.set_defaults(func=cmd_sources_delete_all)

    s = ssub.add_parser("delete-invalid", parents=[COMMON], help="删除失效书源")
    s.set_defaults(func=cmd_sources_delete_invalid)

    s = ssub.add_parser("test", parents=[COMMON], help="测试书源有效性")
    s.add_argument("--keyword", default="", help="测试关键词")
    s.add_argument("--urls", nargs="*", help="限定测试的 bookSourceUrl 列表(默认全部)")
    s.add_argument("--no-mark-invalid", dest="mark_invalid", action="store_false", default=True, help="不把失效书源标记为禁用")
    s.add_argument("--concurrent", type=int, default=12, help="并发数 1-12(默认 12)")
    s.set_defaults(func=cmd_sources_test)

    s = ssub.add_parser("set-default", parents=[COMMON], help="将默认书源应用到指定用户(需管理密码)")
    s.add_argument("-u", "--username", required=True)
    s.set_defaults(func=cmd_sources_set_default)

    # RSS
    sp = sub.add_parser("rss", parents=[COMMON], help="RSS 源管理")
    rsub = sp.add_subparsers(dest="action", metavar="操作", required=True)

    r = rsub.add_parser("list", parents=[COMMON], help="RSS 源列表")
    r.set_defaults(func=cmd_rss_list)

    r = rsub.add_parser("add", parents=[COMMON], help="导入 RSS 源(本地文件/远程URL/标准输入)")
    r.add_argument("path", nargs="?", help="本地文件路径;- 表示 stdin")
    r.add_argument("--remote-url", help="远程 RSS 源文件 URL")
    r.set_defaults(func=cmd_rss_add)

    r = rsub.add_parser("delete", parents=[COMMON], help="删除 RSS 源")
    r.add_argument("-u", "--urls", nargs="*", help="sourceUrl 列表,或用 stdin 逐行传入")
    r.set_defaults(func=cmd_rss_delete)

    # 书架
    sp = sub.add_parser("shelf", parents=[COMMON], help="书架管理(列表/添加/删除)")
    shelf_sub = sp.add_subparsers(dest="action", metavar="操作")

    s_list = shelf_sub.add_parser("list", parents=[COMMON], help="书架列表")
    s_list.set_defaults(func=cmd_shelf_list)

    s_add = shelf_sub.add_parser("add", parents=[COMMON], help="添加书籍到书架")
    s_add.add_argument("-n", "--name", help="书籍名称")
    s_add.add_argument("-a", "--author", default="", help="作者")
    s_add.add_argument("-u", "--book-url", help="书籍详情/主页 URL")
    s_add.add_argument("-o", "--origin", help="书源 URL (origin)")
    s_add.add_argument("--origin-name", help="书源名称")
    s_add.add_argument("--cover-url", help="封面图片 URL")
    s_add.add_argument("--intro", help="书籍简介")
    s_add.add_argument("--group", type=int, help="分组 ID")
    s_add.add_argument("--data", help="JSON 字面量 / @文件 / -(stdin)")
    s_add.set_defaults(func=cmd_shelf_add)

    s_del = shelf_sub.add_parser("delete", parents=[COMMON], help="从书架删除书籍")
    s_del.add_argument("-u", "--book-url", required=True, help="书籍 URL (bookUrl)")
    s_del.add_argument("-n", "--name", help="书籍名称 (可选)")
    s_del.set_defaults(func=cmd_shelf_delete)

    sp.set_defaults(func=cmd_shelf_default)

    # 分组
    sp = sub.add_parser("groups", parents=[COMMON], help="书架分组管理")
    gsub = sp.add_subparsers(dest="action", metavar="操作", required=True)

    g = gsub.add_parser("list", parents=[COMMON], help="分组列表")
    g.set_defaults(func=cmd_groups_list)

    g = gsub.add_parser("add", parents=[COMMON], help="新增分组")
    g.add_argument("-n", "--name", required=True)
    g.add_argument("--id", type=int, default=0, help="groupId(默认自动)")
    g.add_argument("--order", type=int, default=0, help="排序(默认 0)")
    g.set_defaults(func=cmd_groups_add)

    g = gsub.add_parser("delete", parents=[COMMON], help="删除分组")
    g.add_argument("--id", type=int, required=True, help="groupId")
    g.set_defaults(func=cmd_groups_delete)

    # 替换规则
    sp = sub.add_parser("rules", parents=[COMMON], help="替换规则管理")
    rsub2 = sp.add_subparsers(dest="action", metavar="操作", required=True)

    r = rsub2.add_parser("list", parents=[COMMON], help="替换规则列表")
    r.set_defaults(func=cmd_rules_list)

    r = rsub2.add_parser("add", parents=[COMMON], help="添加替换规则(JSON 对象或数组)")
    r.add_argument("data", help="JSON 字面量 / @文件 / -(stdin)")
    r.set_defaults(func=cmd_rules_add)

    r = rsub2.add_parser("delete", parents=[COMMON], help="按 name 删除替换规则")
    r.add_argument("-n", "--name", required=True)
    r.set_defaults(func=cmd_rules_delete)

    # 其他
    sp = sub.add_parser("version", parents=[COMMON], help="检查版本更新")
    sp.add_argument("--force", action="store_true", help="强制检查(忽略缓存)")
    sp.set_defaults(func=cmd_version)

    sp = sub.add_parser("health", parents=[COMMON], help="健康检查")
    sp.set_defaults(func=cmd_health)

    sp = sub.add_parser("raw", parents=[COMMON], help="通用请求: raw <METHOD> <PATH> [--data json|@file|-] [--query k=v]")
    sp.add_argument("method", help="HTTP 方法,如 GET/POST")
    sp.add_argument("path", help="路径,如 /reader3/getUserInfo")
    sp.add_argument("--data", help="请求体: JSON 字面量 / @文件 / -(stdin)")
    sp.add_argument("--query", action="append", default=[], help="query 参数 k=v(可多次指定,如 --query a=1 --query b=2)")
    sp.set_defaults(func=cmd_raw)

    return p


def bool_flag(value):
    if isinstance(value, bool):
        return value
    v = value.strip().lower()
    if v in ("true", "1", "yes", "on"):
        return True
    if v in ("false", "0", "no", "off"):
        return False
    raise argparse.ArgumentTypeError("需要 true/false,收到: %s" % value)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    if not hasattr(args, "json"):
        args.json = False
    client = resolve_client(args)
    try:
        args.func(args, client)
        return 0
    except AdminError as e:
        eprint("错误: %s" % e)
        return 1
    except (OSError, ValueError, json.JSONDecodeError) as e:
        eprint("错误: %s" % e)
        return 1
    except KeyboardInterrupt:
        eprint("已取消")
        return 130
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
