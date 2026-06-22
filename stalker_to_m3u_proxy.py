#!/usr/bin/env python3
"""
Stalker Portal -> M3U proxy  (cloud-host edition: Railway / Render / Fly.io / etc.)
====================================================================================

WHAT THIS DOES
--------------
Your IPTV provider uses the "Stalker Portal" (a.k.a. Ministra) protocol, which
authenticates by MAC address instead of username/password. Samsung TVs don't
speak that protocol, but most IPTV apps (Smart IPTV / SS IPTV, IPTV Smarters,
etc.) understand a plain M3U playlist over HTTP/HTTPS.

This script:
  1. Logs into your Stalker portal using your MAC address.
  2. Pulls your channel list (auto-detects the right API path - panels vary).
  3. Runs a small web server that serves:
       https://<your-app>.up.railway.app/playlist.m3u   -> the channel list
       https://<your-app>.up.railway.app/play/<id>       -> the actual video,
         re-authenticating with the portal fresh on every play, since Stalker
         stream links expire fast and a static playlist alone tends to die
         after a few minutes.

CONFIG — via environment variables (set these in your host's dashboard,
not in this file, so your credentials aren't sitting in plain text):
  PORTAL_URL   e.g. http://your-portal-domain.com
  MAC          e.g. 00:1A:79:XX:XX:XX
  PORT         most hosts (Railway included) set this automatically - leave unset locally

DEPLOY ON RAILWAY (quick version)
----------------------------------
  1. Put this file in a new GitHub repo (or use `railway up` from a local folder
     with just this file in it).
  2. On Railway: New Project -> Deploy from repo (or `railway up`).
  3. In the service's Variables tab, add PORTAL_URL and MAC.
  4. Set the start command to:  python3 stalker_to_m3u_proxy.py
  5. Railway gives you a public URL like https://yourapp.up.railway.app
     -> your playlist is at https://yourapp.up.railway.app/playlist.m3u
  6. On your Samsung TV, open an IPTV app that accepts an M3U URL (Smart IPTV /
     SS IPTV needs you to register the TV's MAC at siptv.app and upload the
     playlist there; IPTV Smarters Player accepts an M3U URL directly) and
     point it at that URL.

No external Python packages are required - standard library only.
"""

import hashlib
import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

# ======================= CONFIG (env vars; placeholders below are just for local testing) =======================
PORTAL_URL = os.environ.get("PORTAL_URL", "http://your-portal-domain.com")
MAC        = os.environ.get("MAC", "00:1A:79:XX:XX:XX")
LOCAL_PORT = int(os.environ.get("PORT", "8088"))   # Railway/Render set PORT automatically
# ===================================================================================================================

SERIAL = hashlib.md5(MAC.encode()).hexdigest().upper()
DEVICE_ID = hashlib.sha256(MAC.encode()).hexdigest().upper()
DEVICE_ID2 = DEVICE_ID

UA = ("Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 "
      "(KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3")


class StalkerClient:
    """Talks to the Stalker/Ministra portal API."""

    # Different panels mount the API at different paths. We try these in order
    # the first time we log in, and stick with whichever one works.
    CANDIDATE_PATHS = [
        "/stalker_portal/c/",
        "/server/load.php",
        "/stalker_portal/server/load.php",
        "/stalker_portal/c/server/load.php",
        "/c/server/load.php",
        "/portal.php",
    ]

    def __init__(self, portal, mac):
        self.portal = portal.rstrip("/")
        self.mac = mac
        self.token = None
        self.api_path = None
        self.lock = threading.Lock()
        self._channel_cache = {}
        self._genre_map = {}

    def _headers(self):
        h = {
            "User-Agent": UA,
            "Cookie": f"mac={self.mac}; stb_lang=en; timezone=Europe/London",
            "Accept": "*/*",
        }
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _request(self, path, params):
        qs = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params.items())
        url = f"{self.portal}{path}?{qs}"
        req = Request(url, headers=self._headers())
        with urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8", "ignore"))

    def _call(self, params, retry=True):
        if self.api_path is None:
            self._detect_path()
        params = {**params, "stb_lang": "en"}
        try:
            data = self._request(self.api_path, params)
        except (HTTPError, URLError) as e:
            raise RuntimeError(f"Portal request failed: {e}")
        js = data.get("js") if isinstance(data, dict) else None
        if js is None and retry:
            self.token = None
            self.login()
            return self._call(params, retry=False)
        return js if js is not None else (data if isinstance(data, dict) else {})

    def _detect_path(self):
        for candidate in self.CANDIDATE_PATHS:
            try:
                data = self._request(candidate, {
                    "type": "stb", "action": "handshake", "token": "",
                    "JsHttpRequest": "1-xml", "stb_lang": "en",
                })
                token = (data.get("js") or {}).get("token") if isinstance(data, dict) else None
                if token:
                    self.api_path = candidate
                    self.token = token
                    return
            except Exception:
                continue
        raise RuntimeError(
            "Could not reach the portal's API on any known path. Double-check PORTAL_URL "
            "(it should be the base domain your IPTV seller gave you, e.g. http://example.com)."
        )

    def login(self):
        with self.lock:
            self.token = None
            self.api_path = None
            self._detect_path()
            self._call({
                "type": "stb", "action": "get_profile", "hd": "1",
                "ver": "ImageDescription: 0.2.18-r14-pub-250; ",
                "num_banks": "2", "sn": SERIAL, "stb_type": "MAG250",
                "client_type": "STB", "image_version": "218",
                "video_out": "hdmi", "device_id": DEVICE_ID, "device_id2": DEVICE_ID2,
                "signature": "", "auth_second_step": "1", "hw_version": "1.7-BD-00",
                "not_valid_token": "0", "metrics": "{}", "hw_version_2": "",
                "timestamp": int(time.time()), "api_sig": "263", "JsHttpRequest": "1-xml",
            }, retry=False)

    def get_genre_map(self):
        if self._genre_map:
            return self._genre_map
        try:
            js = self._call({"type": "itv", "action": "get_genres", "JsHttpRequest": "1-xml"})
            data = js.get("data", []) if isinstance(js, dict) else []
            self._genre_map = {str(g.get("id")): g.get("title", "") for g in data}
        except Exception:
            self._genre_map = {}
        return self._genre_map

    def get_channels(self):
        if self.token is None:
            self.login()
        js = self._call({"type": "itv", "action": "get_all_channels", "JsHttpRequest": "1-xml"})
        items = js.get("data", []) if isinstance(js, dict) else []
        if not items:
            items = self._get_channels_by_genre()
        self._channel_cache = {str(c["id"]): c for c in items}
        return items

    def _get_channels_by_genre(self):
        genre_map = self.get_genre_map()
        all_items, seen = [], set()
        for gid in genre_map:
            page = 1
            while page <= 50:  # safety cap
                js = self._call({
                    "type": "itv", "action": "get_ordered_list",
                    "genre": gid, "p": page, "JsHttpRequest": "1-xml",
                })
                data = js.get("data", []) if isinstance(js, dict) else []
                if not data:
                    break
                for c in data:
                    if c.get("id") not in seen:
                        seen.add(c.get("id"))
                        all_items.append(c)
                page += 1
        return all_items

    def create_link(self, channel_id):
        if self.token is None:
            self.login()
        chan = self._channel_cache.get(str(channel_id))
        if not chan:
            self.get_channels()
            chan = self._channel_cache.get(str(channel_id))
        if not chan:
            raise RuntimeError("Unknown channel id")
        js = self._call({"type": "itv", "action": "create_link", "cmd": chan["cmd"], "JsHttpRequest": "1-xml"})
        real_cmd = js.get("cmd", "") if isinstance(js, dict) else ""
        parts = real_cmd.split()
        return parts[-1] if parts else real_cmd


client = StalkerClient(PORTAL_URL, MAC)


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # quiet logs

    def do_GET(self):
        if self.path.startswith("/playlist.m3u"):
            self.serve_playlist()
        elif self.path.startswith("/play/"):
            self.serve_stream()
        elif self.path == "/" or self.path.startswith("/health"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_error(404)

    def serve_playlist(self):
        try:
            channels = client.get_channels()
            genre_map = client.get_genre_map()
        except Exception as e:
            self.send_error(502, f"Could not reach portal: {e}")
            return
        # Use the Host header the request actually came in on (works behind
        # Railway/Render's reverse proxy, which terminates HTTPS for you).
        host = self.headers.get("Host", f"{local_ip()}:{LOCAL_PORT}")
        scheme = "https" if self.headers.get("X-Forwarded-Proto") == "https" else "http"
        lines = ["#EXTM3U"]
        for c in channels:
            name = c.get("name", "Unknown")
            logo = c.get("logo", "")
            cid = c.get("id")
            group = genre_map.get(str(c.get("tv_genre_id")), "")
            lines.append(f'#EXTINF:-1 tvg-logo="{logo}" group-title="{group}",{name}')
            lines.append(f"{scheme}://{host}/play/{cid}")
        body = "\n".join(lines).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "audio/x-mpegurl")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def serve_stream(self):
        cid = self.path.split("/play/")[-1].split("?")[0]
        try:
            real_url = client.create_link(cid)
        except Exception as e:
            self.send_error(502, f"Could not get stream: {e}")
            return
        try:
            req = Request(real_url, headers={"User-Agent": UA})
            with urlopen(req, timeout=15) as upstream:
                self.send_response(200)
                ctype = upstream.headers.get("Content-Type", "video/mp2t")
                self.send_header("Content-Type", ctype)
                self.end_headers()
                while True:
                    chunk = upstream.read(65536)
                    if not chunk:
                        break
                    try:
                        self.wfile.write(chunk)
                    except (BrokenPipeError, ConnectionResetError):
                        break
        except (HTTPError, URLError) as e:
            self.send_error(502, f"Upstream error: {e}")


if __name__ == "__main__":
    print("Logging into your Stalker portal...")
    try:
        client.login()
        chans = client.get_channels()
        print(f"Success - found {len(chans)} channels.")
    except Exception as e:
        print(f"Could not log in: {e}")
        print("Double check the PORTAL_URL and MAC environment variables.")
        # Don't exit on a cloud host - keep the server up so you can see the
        # error by hitting / , and so the host doesn't think the deploy crashed.
        # (Remove the next line if you'd rather it hard-fail on bad config.)
    server = ThreadingHTTPServer(("0.0.0.0", LOCAL_PORT), Handler)
    print(f"Listening on 0.0.0.0:{LOCAL_PORT}  ->  /playlist.m3u is your TV's playlist URL")
    server.serve_forever()
