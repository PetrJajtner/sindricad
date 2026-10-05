#!/usr/bin/env python3
"""SindriCAD web gateway — serves the built frontend to browsers on the LAN and
gives every browser session its own geometry sidecar.

    browser ──https──▶ gateway ──ws 127.0.0.1:<port>──▶ sidecar (one per session)

What it does
  * serves the production frontend (`npm run build` → dist/)
  * a cookie identifies the browser session; each session gets its own folder
    (exports/, cache/, tmp/) and, on its first WebSocket, its own sidecar on a
    free loopback port with a fresh random token
  * proxies /__sindri/ws to that sidecar, adding the token itself, so the
    browser never sees one
  * /__sindri/export-dir and /__sindri/download serve the session's exports
    (the frontend half lives in src/io/files.ts)
  * stops sidecars idle for --idle-minutes, deletes session folders unused for
    --keep-hours, refuses new sessions above --max-sessions
  * optional: TLS (--cert/--key), a shared password (SINDRI_WEB_PASSWORD, HTTP
    Basic), bubblewrap sandbox for sidecars (--sandbox)

Run (from the repo):  web/.venv/bin/python web/gateway.py --help
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import mimetypes
import os
import re
import secrets
import shutil
import signal
import socket
import ssl
import sys
import time
import zipfile
from pathlib import Path
from urllib.parse import quote, urlsplit

import aiohttp
from aiohttp import WSMsgType, web

# Python's mimetypes table does not know .wasm everywhere, and the frontend's
# sketch solver is WebAssembly: a wrong type breaks instantiateStreaming.
mimetypes.add_type("application/wasm", ".wasm")
mimetypes.add_type("text/javascript", ".mjs")

log = logging.getLogger("gateway")

COOKIE = "sindri_sid"
SID_RE = re.compile(r"^[A-Za-z0-9_-]{32}$")
# The sidecar caps a frame at 128 MiB; give the proxy a little headroom.
MAX_MSG = 160 * 1024 * 1024
WS_PATHS = ("/__sindri/ws", "/__sindri/ws/")


# ---- .sindri container -------------------------------------------------------
# The same ZIP the desktop app writes and reads (src-tauri/src/container.rs), so a
# file saved in the browser opens at home in the desktop app and vice versa:
#   manifest.json      STORED, first
#   document.json      DEFLATE
#   geom/<hash>.bbrep  DEFLATE, the blob named by its BLAKE2b-128 hash
#   mesh/<key>.bin     optional reopen cache: never written here, skipped on read
CONTAINER_VERSION = 1
HASH_ALG = "blake2b-128"
HASH_RE = re.compile(r"^[0-9a-f]{32}$")
MAX_UNCOMPRESSED = 4 << 30  # refuse archives that would expand past this


class ContainerError(Exception):
    """A user-facing reason a document could not be saved or opened."""


def _new_hash():
    return hashlib.blake2b(digest_size=16)


def write_container(dest: Path, document_json: str, blob_dir: Path, hashes: list[str]) -> None:
    rows, missing = [], []
    for h in sorted(set(hashes)):
        p = blob_dir / f"{h}.bbrep"
        if p.is_file():
            rows.append({"entry": f"geom/{h}.bbrep", "hash": h, "bytes": p.stat().st_size})
        else:
            missing.append(h)
    if missing:
        # Same rule as the desktop: never write a file whose geometry is not in it.
        raise ContainerError(
            f"{len(missing)} of this document's imported bodies could not be found on the "
            "server (the session folder may have been cleaned up), so saving was stopped "
            "rather than writing a file with missing geometry.")
    manifest = {"container": CONTAINER_VERSION, "hashAlg": HASH_ALG, "app": "sindricad-web",
                "blobs": rows, "meshes": []}
    tmp = dest.with_name(f"{dest.name}.tmp-{secrets.token_hex(6)}")
    try:
        with zipfile.ZipFile(tmp, "w") as z:
            z.writestr("manifest.json", json.dumps(manifest, indent=2), compress_type=zipfile.ZIP_STORED)
            z.writestr("document.json", document_json, compress_type=zipfile.ZIP_DEFLATED)
            for r in rows:
                z.write(blob_dir / f"{r['hash']}.bbrep", r["entry"], compress_type=zipfile.ZIP_DEFLATED)
        os.replace(tmp, dest)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def read_container(src: Path, blob_dir: Path) -> str:
    """Extract a container's geometry into blob_dir (verifying every hash) and
    return its document JSON. Blob files are named by the VERIFIED hash, never by
    a name from inside the archive, so zip-slip cannot happen."""
    damaged = "This document is damaged and cannot be opened."
    try:
        z = zipfile.ZipFile(src)
    except (zipfile.BadZipFile, OSError):
        raise ContainerError(damaged) from None
    with z:
        if sum(i.file_size for i in z.infolist()) > MAX_UNCOMPRESSED:
            raise ContainerError(f"This document expands to more than {MAX_UNCOMPRESSED >> 30} GiB and was refused.")
        try:
            manifest = json.loads(z.read("manifest.json"))
        except KeyError:
            raise ContainerError("This document is missing its manifest and cannot be opened.") from None
        except ValueError:
            raise ContainerError("This document has an unreadable manifest and cannot be opened.") from None
        if not isinstance(manifest, dict):
            raise ContainerError("This document has an unreadable manifest and cannot be opened.")
        version = manifest.get("container")
        if not isinstance(version, int) or version > CONTAINER_VERSION:
            raise ContainerError(f"This document uses a newer SindriCAD container format (v{version}). "
                                 "The server's SindriCAD needs an update to open it.")
        if manifest.get("hashAlg") != HASH_ALG:
            raise ContainerError(f"This document uses an unsupported hash ({manifest.get('hashAlg')}).")
        try:
            document_json = z.read("document.json").decode("utf-8")
        except KeyError:
            raise ContainerError("This document is missing its contents and cannot be opened.") from None
        except (UnicodeDecodeError, zipfile.BadZipFile, OSError):
            raise ContainerError(damaged) from None

        blob_dir.mkdir(parents=True, exist_ok=True)
        for row in manifest.get("blobs") or []:
            h = row.get("hash", "") if isinstance(row, dict) else ""
            entry = row.get("entry", "") if isinstance(row, dict) else ""
            if not HASH_RE.match(h) or not isinstance(entry, str):
                raise ContainerError(damaged)
            final = blob_dir / f"{h}.bbrep"
            if final.exists():
                continue  # same hash => same bytes
            tmp = blob_dir / f"{h}.bbrep.tmp-{secrets.token_hex(6)}"
            digest = _new_hash()
            try:
                with z.open(entry) as fsrc, open(tmp, "wb") as fout:
                    while chunk := fsrc.read(1 << 20):
                        digest.update(chunk)
                        fout.write(chunk)
                if digest.hexdigest() != h:
                    raise ContainerError(
                        "This document's geometry does not match its manifest - the file is damaged "
                        "or was modified. Opening it was refused rather than showing you the wrong shape.")
                os.replace(tmp, final)
            except KeyError:
                tmp.unlink(missing_ok=True)
                raise ContainerError(f"This document is missing part of its geometry ({entry}).") from None
            except (zipfile.BadZipFile, OSError):
                tmp.unlink(missing_ok=True)
                raise ContainerError(damaged) from None
            except BaseException:
                tmp.unlink(missing_ok=True)
                raise
    return document_json


def safe_name(raw: str, fallback: str) -> str:
    name = re.sub(r"[^\w.\- ()]", "_", os.path.basename(raw or "")).strip(" .")
    return (name or fallback)[-120:]


class Full(Exception):
    """No room for another sidecar right now."""


class Session:
    def __init__(self, sid: str, root: Path):
        self.sid = sid
        self.dir = root / sid
        self.exports = self.dir / "exports"
        self.proc: asyncio.subprocess.Process | None = None
        self.port: int | None = None
        self.token: str | None = None
        self.conns = 0
        self.last_seen = time.time()
        self.lock = asyncio.Lock()
        self.pumps: list[asyncio.Task] = []

    @property
    def tag(self) -> str:
        return self.sid[:6]

    @property
    def running(self) -> bool:
        return self.proc is not None and self.proc.returncode is None

    def touch(self) -> None:
        self.last_seen = time.time()

    def ensure_dirs(self) -> None:
        for sub in ("exports", "cache", "tmp", "blobs", "uploads"):
            (self.dir / sub).mkdir(parents=True, exist_ok=True)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Gateway:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.sidecar_dir = Path(args.sidecar).resolve()
        self.python = Path(args.python).absolute() if args.python else self.sidecar_dir / ".venv" / "bin" / "python"
        self.dist = Path(args.dist).resolve()
        self.data = Path(args.data).resolve()
        self.sessions: dict[str, Session] = {}
        self.password = os.environ.get("SINDRI_WEB_PASSWORD") or ""
        self.http: aiohttp.ClientSession | None = None
        self.secure = bool(args.cert)
        self.bwrap = shutil.which("bwrap") if args.sandbox else None

    # ---- sanity --------------------------------------------------------------
    def check(self) -> None:
        problems = []
        if not (self.sidecar_dir / "server.py").is_file():
            problems.append(f"sidecar not found: {self.sidecar_dir}/server.py")
        if not self.python.exists():
            problems.append(f"sidecar python not found: {self.python} (run `uv sync` in the sidecar folder)")
        if not (self.dist / "index.html").is_file():
            problems.append(f"frontend build not found: {self.dist}/index.html (run the build first)")
        if self.args.sandbox and not self.bwrap:
            problems.append("--sandbox needs bubblewrap: sudo apt install bubblewrap")
        if problems:
            for p in problems:
                log.error(p)
            sys.exit(2)
        self.data.mkdir(parents=True, exist_ok=True)
        if self.args.host not in ("127.0.0.1", "localhost", "::1") and not self.args.cert:
            log.warning("listening on %s WITHOUT TLS: put Apache/nginx in front, or use --cert/--key",
                        self.args.host)
        if not self.args.sandbox:
            log.warning("sidecars run WITHOUT a sandbox: a sidecar can write anywhere this user can. "
                        "Fine for testing at home; use --sandbox for students.")

    # ---- sessions ------------------------------------------------------------
    def session(self, sid: str, create: bool = True) -> Session | None:
        s = self.sessions.get(sid)
        if s is None and create:
            s = self.sessions[sid] = Session(sid, self.data)
        return s

    def running_count(self) -> int:
        return sum(1 for s in self.sessions.values() if s.running)

    def has_room_for(self, s: Session) -> bool:
        return s.running or self.running_count() < self.args.max_sessions

    def _command(self, s: Session) -> list[str]:
        cmd = [str(self.python), "server.py"]
        if not self.bwrap:
            return cmd
        # Read-only view of the whole system; writable only: this session's
        # folder and a private /tmp. Network stays shared because the gateway
        # reaches the sidecar over 127.0.0.1.
        return [
            self.bwrap,
            "--ro-bind", "/", "/",
            "--dev", "/dev",
            "--tmpfs", "/dev/shm",
            "--proc", "/proc",
            "--tmpfs", "/tmp",
            "--bind", str(s.dir), str(s.dir),
            "--unshare-pid", "--unshare-ipc", "--unshare-uts",
            "--die-with-parent", "--new-session",
            "--chdir", str(self.sidecar_dir),
            "--", *cmd,
        ]

    def _env(self, s: Session, port: int, token: str) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items()
               if k in ("PATH", "HOME", "LANG", "LC_ALL", "USER", "LOGNAME")}
        env.update({
            "SINDRI_SIDECAR_PORT": str(port),
            "SINDRI_SIDECAR_TOKEN": token,
            "XDG_CACHE_HOME": str(s.dir / "cache"),
            "SINDRI_CACHE_MAX_GB": str(self.args.cache_gb),
            "TMPDIR": str(s.dir / "tmp"),
            "PYTHONUNBUFFERED": "1",
            # The rest mirrors what the desktop shell sets (src-tauri/src/sidecar.rs).
            # Imported geometry goes to the session, where Save can pack it.
            "SINDRI_BLOB_DIR": str(s.dir / "blobs"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONUTF8": "1",
            "OPENBLAS_NUM_THREADS": "1",
            "OMP_NUM_THREADS": "1",
            "MKL_NUM_THREADS": "1",
        })
        return env

    async def ensure_sidecar(self, s: Session) -> None:
        async with s.lock:
            if s.running:
                return
            if not self.has_room_for(s):
                self.evict_one_idle()
            if not self.has_room_for(s):
                raise Full()
            s.ensure_dirs()
            for attempt in range(3):
                port, token = free_port(), secrets.token_urlsafe(32)
                log.info("[%s] starting sidecar on port %d", s.tag, port)
                proc = await asyncio.create_subprocess_exec(
                    *self._command(s), cwd=self.sidecar_dir, env=self._env(s, port, token),
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                    start_new_session=True,
                )
                if await self._wait_listening(s, proc, port):
                    s.proc, s.port, s.token = proc, port, token
                    s.pumps = [asyncio.create_task(self._drain(s, proc))]
                    return
                code = proc.returncode
                if code is None:
                    await self._stop_proc(proc)
                if code != 3:  # 3 = port in use: retry with another port; anything else is real
                    break
            raise RuntimeError("sidecar did not start (see the log above)")

    async def _wait_listening(self, s: Session, proc: asyncio.subprocess.Process, port: int) -> bool:
        deadline = time.monotonic() + self.args.start_timeout
        assert proc.stdout
        while time.monotonic() < deadline:
            try:
                line = await asyncio.wait_for(proc.stdout.readline(), deadline - time.monotonic())
            except asyncio.TimeoutError:
                break
            if not line:  # process exited
                await proc.wait()
                log.error("[%s] sidecar exited with code %s before listening", s.tag, proc.returncode)
                return False
            text = line.decode(errors="replace").rstrip()
            log.info("[%s] %s", s.tag, text)
            if text.strip() == f"LISTENING {port}":
                return True
        log.error("[%s] sidecar not listening after %ss", s.tag, self.args.start_timeout)
        return False

    async def _drain(self, s: Session, proc: asyncio.subprocess.Process) -> None:
        """Keep reading the sidecar's output (a full pipe would block it)."""
        assert proc.stdout
        async for line in proc.stdout:
            log.info("[%s] %s", s.tag, line.decode(errors="replace").rstrip())
        code = await proc.wait()
        log.info("[%s] sidecar exited (code %s)", s.tag, code)

    async def _stop_proc(self, proc: asyncio.subprocess.Process) -> None:
        if proc.returncode is not None:
            return
        try:
            os.killpg(proc.pid, signal.SIGTERM)  # the whole group: sidecar + its worker
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(proc.wait(), 5)
        except asyncio.TimeoutError:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await proc.wait()

    async def stop_sidecar(self, s: Session, why: str) -> None:
        if s.proc is None:
            return
        log.info("[%s] stopping sidecar (%s)", s.tag, why)
        await self._stop_proc(s.proc)
        s.proc = s.port = s.token = None

    def evict_one_idle(self) -> None:
        idle = [x for x in self.sessions.values() if x.running and x.conns == 0]
        if idle:
            victim = min(idle, key=lambda x: x.last_seen)
            proc = victim.proc
            log.info("[%s] stopping idle sidecar to make room", victim.tag)
            # Counts as free immediately; the stop itself finishes in the background.
            victim.proc = victim.port = victim.token = None
            asyncio.create_task(self._stop_proc(proc))

    async def reaper(self) -> None:
        while True:
            await asyncio.sleep(60)
            now = time.time()
            for s in list(self.sessions.values()):
                if s.running and s.conns == 0 and now - s.last_seen > self.args.idle_minutes * 60:
                    await self.stop_sidecar(s, "idle")
                if not s.running and s.conns == 0 and now - s.last_seen > self.args.keep_hours * 3600:
                    shutil.rmtree(s.dir, ignore_errors=True)
                    self.sessions.pop(s.sid, None)
                    log.info("[%s] session folder removed", s.tag)

    def sweep_old_dirs(self) -> None:
        """At start-up: drop session folders left from a previous run and unused for --keep-hours."""
        limit = time.time() - self.args.keep_hours * 3600
        for d in self.data.iterdir():
            if d.is_dir() and SID_RE.match(d.name) and d.stat().st_mtime < limit:
                shutil.rmtree(d, ignore_errors=True)

    # ---- HTTP ----------------------------------------------------------------
    @web.middleware
    async def middleware(self, request: web.Request, handler):
        if self.password and not self._auth_ok(request):
            return web.Response(status=401, text="Login required",
                                headers={"WWW-Authenticate": 'Basic realm="SindriCAD", charset="UTF-8"'})
        sid = request.cookies.get(COOKIE, "")
        fresh = not SID_RE.match(sid)
        if fresh:
            sid = secrets.token_urlsafe(24)  # 32 chars
        request["sid"] = sid
        resp = await handler(request)
        if fresh and not isinstance(resp, web.WebSocketResponse):
            # Behind Apache/nginx the browser talks HTTPS to the proxy, not to us;
            # the proxy says so in X-Forwarded-Proto. Trusting that header is safe
            # only because a proxied gateway listens on 127.0.0.1.
            secure = self.secure or request.headers.get("X-Forwarded-Proto", "").lower() == "https"
            resp.set_cookie(COOKIE, sid, httponly=True, samesite="Strict", secure=secure,
                            max_age=self.args.keep_hours * 3600, path="/")
        return resp

    def _auth_ok(self, request: web.Request) -> bool:
        h = request.headers.get("Authorization", "")
        if not h.startswith("Basic "):
            return False
        try:
            _, _, pw = base64.b64decode(h[6:]).decode().partition(":")
        except Exception:
            return False
        return hmac.compare_digest(pw.encode(), self.password.encode())

    async def index(self, request: web.Request) -> web.StreamResponse:
        s = self.session(request["sid"])
        s.touch()
        if not self.has_room_for(s) and not any(x.running and x.conns == 0 for x in self.sessions.values()):
            return web.Response(status=503, content_type="text/html", charset="utf-8", text=FULL_PAGE)
        return web.FileResponse(self.dist / "index.html", headers={"Cache-Control": "no-cache"})

    async def export_dir(self, request: web.Request) -> web.Response:
        s = self.session(request["sid"])
        s.ensure_dirs()
        s.touch()
        return web.json_response({"dir": str(s.exports)}, headers={"Cache-Control": "no-store"})

    async def download(self, request: web.Request) -> web.StreamResponse:
        s = self.session(request["sid"], create=False)
        name = os.path.basename(request.query.get("name", ""))
        if s is None or not name:
            raise web.HTTPNotFound()
        f = s.exports / name
        if not f.is_file():
            raise web.HTTPNotFound()
        s.touch()
        ascii_name = re.sub(r'[^\x20-\x7e]|["\\]', "_", name)
        return web.FileResponse(f, headers={
            "Content-Type": "application/octet-stream",
            "Content-Disposition": f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(name)}",
            "Cache-Control": "no-store",
        })

    def _cross_origin(self, request: web.Request) -> bool:
        origin = request.headers.get("Origin", "")
        return bool(origin) and urlsplit(origin).netloc != request.host

    async def _receive(self, request: web.Request, dest: Path) -> int:
        """Stream a request body to dest (atomically), enforcing --max-upload-mb."""
        limit = int(self.args.max_upload_mb * 1024 * 1024)
        if request.content_length and request.content_length > limit:
            raise web.HTTPRequestEntityTooLarge(max_size=limit, actual_size=request.content_length)
        tmp = dest.with_name(f".{dest.name}.part-{secrets.token_hex(4)}")
        size = 0
        try:
            with open(tmp, "wb") as f:
                async for chunk in request.content.iter_chunked(1 << 16):
                    size += len(chunk)
                    if size > limit:
                        raise web.HTTPRequestEntityTooLarge(max_size=limit, actual_size=size)
                    f.write(chunk)
            os.replace(tmp, dest)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        return size

    async def upload(self, request: web.Request) -> web.Response:
        """A model file for Import: lands in the session's uploads/, where the
        sidecar reads it by path like the desktop app reads a local file."""
        if self._cross_origin(request):
            raise web.HTTPForbidden(text="bad origin")
        s = self.session(request["sid"])
        s.ensure_dirs()
        s.touch()
        name = safe_name(request.query.get("name", ""), "upload")
        dest = s.dir / "uploads" / name
        size = await self._receive(request, dest)
        log.info("[%s] uploaded %s (%d bytes)", s.tag, name, size)
        return web.json_response({"path": str(dest), "name": name})

    async def save(self, request: web.Request) -> web.StreamResponse:
        """Pack the document and its imported geometry into a .sindri container."""
        if self._cross_origin(request):
            raise web.HTTPForbidden(text="bad origin")
        s = self.session(request["sid"])
        s.ensure_dirs()
        s.touch()
        try:
            body = await request.json()
        except ValueError:
            raise web.HTTPBadRequest(text="bad request")
        doc, hashes = body.get("document"), body.get("hashes") or []
        if (not isinstance(doc, str) or not isinstance(hashes, list)
                or not all(isinstance(h, str) and HASH_RE.match(h) for h in hashes)):
            raise web.HTTPBadRequest(text="bad request")
        name = safe_name(str(body.get("name") or ""), "model")
        if not name.lower().endswith(".sindri"):
            name += ".sindri"
        out = s.dir / "tmp" / f"save-{secrets.token_hex(6)}.sindri"
        try:
            await asyncio.to_thread(write_container, out, doc, s.dir / "blobs", hashes)
        except ContainerError as e:
            return web.json_response({"error": str(e)}, status=409)
        asyncio.get_running_loop().call_later(300, lambda: out.unlink(missing_ok=True))
        ascii_name = re.sub(r'[^\x20-\x7e]|["\\]', "_", name)
        return web.FileResponse(out, headers={
            "Content-Type": "application/octet-stream",
            "Content-Disposition": f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(name)}",
            "Cache-Control": "no-store",
        })

    async def open_document(self, request: web.Request) -> web.Response:
        """Unpack an uploaded .sindri container: geometry into the session's
        blob store, document JSON back to the page."""
        if self._cross_origin(request):
            raise web.HTTPForbidden(text="bad origin")
        s = self.session(request["sid"])
        s.ensure_dirs()
        s.touch()
        tmp = s.dir / "tmp" / f"open-{secrets.token_hex(6)}.sindri"
        try:
            await self._receive(request, tmp)
            doc = await asyncio.to_thread(read_container, tmp, s.dir / "blobs")
        except ContainerError as e:
            return web.json_response({"error": str(e)}, status=422)
        finally:
            tmp.unlink(missing_ok=True)
        return web.Response(text=doc, content_type="application/json", headers={"Cache-Control": "no-store"})

    async def ws(self, request: web.Request) -> web.StreamResponse:
        # Same-origin only: the session rides on a cookie, so a page from
        # another site must not be able to open this socket in the student's name.
        origin = request.headers.get("Origin", "")
        if not origin or urlsplit(origin).netloc != request.host:
            log.warning("rejected WebSocket from origin %r (host %r)", origin, request.host)
            raise web.HTTPForbidden(text="bad origin")
        if not SID_RE.match(request.cookies.get(COOKIE, "")):
            raise web.HTTPForbidden(text="no session (reload the page)")
        s = self.session(request["sid"])
        try:
            await self.ensure_sidecar(s)
        except Full:
            log.warning("[%s] refused: %d sidecars already running", s.tag, self.running_count())
            raise web.HTTPServiceUnavailable(text="server full")
        except Exception as e:
            log.error("[%s] %s", s.tag, e)
            raise web.HTTPInternalServerError(text="sidecar failed to start")

        client = web.WebSocketResponse(max_msg_size=MAX_MSG, compress=False, heartbeat=30)
        await client.prepare(request)
        s.conns += 1
        s.touch()
        assert self.http
        try:
            async with self.http.ws_connect(
                f"ws://127.0.0.1:{s.port}/?token={quote(s.token or '')}",
                max_msg_size=MAX_MSG, compress=0, autoping=True,
            ) as up:
                async def to_sidecar():
                    async for m in client:
                        s.touch()
                        if m.type == WSMsgType.TEXT:
                            await up.send_str(m.data)
                        elif m.type == WSMsgType.BINARY:
                            await up.send_bytes(m.data)
                        else:
                            break

                async def to_browser():
                    async for m in up:
                        if m.type == WSMsgType.TEXT:
                            await client.send_str(m.data)
                        elif m.type == WSMsgType.BINARY:
                            await client.send_bytes(m.data)
                        else:
                            break

                tasks = [asyncio.create_task(to_sidecar()), asyncio.create_task(to_browser())]
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for t in pending:
                    t.cancel()
                for t in done:
                    if t.exception():
                        log.info("[%s] proxy: %r", s.tag, t.exception())
                if up.close_code and not client.closed:
                    await client.close(code=up.close_code, message=b"sidecar closed")
        except aiohttp.ClientError as e:
            log.error("[%s] cannot reach sidecar: %r", s.tag, e)
        finally:
            s.conns -= 1
            s.touch()
            if not client.closed:
                await client.close()
        return client

    # ---- app -----------------------------------------------------------------
    async def on_startup(self, app: web.Application) -> None:
        self.http = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=None, connect=30))
        self.sweep_old_dirs()
        app["reaper"] = asyncio.create_task(self.reaper())

    async def on_cleanup(self, app: web.Application) -> None:
        app["reaper"].cancel()
        for s in list(self.sessions.values()):
            await self.stop_sidecar(s, "gateway shutting down")
        if self.http:
            await self.http.close()

    def app(self) -> web.Application:
        app = web.Application(middlewares=[self.middleware], client_max_size=64 * 1024 * 1024)
        app.router.add_get("/", self.index)
        app.router.add_get("/index.html", self.index)
        app.router.add_get("/__sindri/export-dir", self.export_dir)
        app.router.add_get("/__sindri/download", self.download)
        app.router.add_post("/__sindri/upload", self.upload)
        app.router.add_post("/__sindri/save", self.save)
        app.router.add_post("/__sindri/open", self.open_document)
        for p in WS_PATHS:
            app.router.add_get(p, self.ws)
        app.router.add_static("/", self.dist, show_index=False, follow_symlinks=False)
        app.on_startup.append(self.on_startup)
        app.on_cleanup.append(self.on_cleanup)
        return app


FULL_PAGE = """<!doctype html><meta charset="utf-8"><title>SindriCAD</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:15vh auto;padding:0 1rem;line-height:1.5">
<h1>Server je teď plný</h1>
<p>Všechna místa jsou obsazená. Zkus to prosím za pár minut znovu, nebo požádej
vedoucího kroužku, aby uvolnil místo.</p>
<p><a href="/">Zkusit znovu</a></p>"""


def parse_args() -> argparse.Namespace:
    here = Path(__file__).resolve().parent
    repo = here.parent
    p = argparse.ArgumentParser(description="SindriCAD web gateway")
    p.add_argument("--host", default="127.0.0.1", help="address to listen on (0.0.0.0 = whole LAN)")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--cert", help="TLS certificate (PEM); with --key enables HTTPS")
    p.add_argument("--key", help="TLS private key (PEM)")
    p.add_argument("--dist", default=str(repo / "dist"), help="built frontend folder")
    p.add_argument("--sidecar", default=str(repo / "sidecar"), help="sidecar folder (server.py)")
    p.add_argument("--python", help="python for the sidecar (default: <sidecar>/.venv/bin/python)")
    p.add_argument("--data", default=str(Path.home() / "sindri-web-data"), help="session folders")
    p.add_argument("--max-sessions", type=int, default=2, help="sidecars running at once")
    p.add_argument("--idle-minutes", type=float, default=20, help="stop a sidecar with no browser this long")
    p.add_argument("--keep-hours", type=float, default=24, help="delete session folders unused this long")
    p.add_argument("--cache-gb", type=float, default=0.5, help="disk cache cap per session")
    p.add_argument("--start-timeout", type=float, default=90, help="seconds to wait for a sidecar to start")
    p.add_argument("--max-upload-mb", type=float, default=200, help="largest file a browser may upload")
    p.add_argument("--sandbox", action="store_true", help="run sidecars in bubblewrap (recommended for students)")
    return p.parse_args()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = parse_args()
    gw = Gateway(args)
    gw.check()
    ctx = None
    if args.cert:
        if not args.key:
            sys.exit("--cert needs --key")
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(args.cert, args.key)
    scheme = "https" if ctx else "http"
    log.info("serving %s on %s://%s:%d (max %d sessions, sandbox %s, password %s)",
             gw.dist, scheme, args.host, args.port, args.max_sessions,
             "on" if gw.bwrap else "OFF", "on" if gw.password else "off")
    web.run_app(gw.app(), host=args.host, port=args.port, ssl_context=ctx,
                print=None, access_log=None, handle_signals=True)


if __name__ == "__main__":
    main()
