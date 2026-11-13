"""End-to-end self-check: python3 test_bridge.py (stdlib only, ~20s)."""
import base64, hashlib, hmac, http.client, json, os, secrets, subprocess, sys, tempfile, threading, time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
PW = "test-owner-password"
HOOK = "waha-hmac-test"
ENV = dict(os.environ, PUBLIC_URL="http://127.0.0.1:18080", PORT="18080",
           OWNER_PASSWORD_SHA256=hashlib.sha256(PW.encode()).hexdigest(),
           ALLOWED_CHATS="synthetic:test,synthetic:quiet", SEND_CHATS="synthetic:test", SEND_ENABLED="true",
           SEND_NEW_CHATS="false", WAHA_URL="http://127.0.0.1:1",
           WAHA_WEBHOOK_HMAC=HOOK, WAHA_API_KEY="", ALLOW_INSECURE_CALLBACKS_FOR_TESTS="1")
SECRET = "whsec_" + base64.b64encode(secrets.token_bytes(32)).decode()
got, fail_next = [], [0]


class Receiver(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_POST(self):
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        mid, ts = self.headers["webhook-id"], self.headers["webhook-timestamp"]
        key = base64.b64decode(SECRET[6:])
        want = "v1," + base64.b64encode(hmac.new(key, f"{mid}.{ts}.".encode() + raw, hashlib.sha256).digest()).decode()
        assert want in self.headers["webhook-signature"].split(" "), "bad signature"
        assert self.headers["X-MCP-Subscription-Id"].startswith("sub_")
        body = json.loads(raw)
        if fail_next[0]:
            fail_next[0] -= 1
            self.send_response(500); self.send_header("Content-Length", "0"); self.end_headers(); return
        got.append(body)
        out = json.dumps({"challenge": body["challenge"]} if body.get("type") == "verification" else {}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)


def req(method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", 18080, timeout=10)
    c.request(method, path, body, headers or {})
    r = c.getresponse()
    return r.status, dict(r.getheaders()), r.read()


def form(path, d):
    return req("POST", path, urllib.parse.urlencode(d), {"Content-Type": "application/x-www-form-urlencoded"})


def wait_for(pred, t=15):
    end = time.time() + t
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.2)
    return False


def py(code):
    return subprocess.run([sys.executable, "-c", "import app; app.init_db(); " + code], cwd=HERE, env=ENV,
                          capture_output=True, text=True, check=True).stdout.strip()


def main(db_dir):
    ENV["DB_PATH"] = os.path.join(db_dir, "t.db")
    rs = ThreadingHTTPServer(("127.0.0.1", 18081), Receiver)
    threading.Thread(target=rs.serve_forever, daemon=True).start()
    srv = subprocess.Popen([sys.executable, "app.py", "serve"], cwd=HERE, env=ENV)
    try:
        assert wait_for(lambda: _up())
        # OAuth: DCR -> authorize -> token
        redirect = "https://chatgpt.com/connector_platform_oauth_redirect"
        assert req("POST", "/register", json.dumps({"redirect_uris": ["https://evil.example/cb"]}))[0] == 400
        assert req("POST", "/register", json.dumps({"redirect_uris": ["https://chatgpt.com/x\r\nSet-Cookie: a=b"]}))[0] == 400
        cid = json.loads(req("POST", "/register", json.dumps({"redirect_uris": [redirect]}))[2])["client_id"]
        verifier = secrets.token_urlsafe(40)
        chal = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        q = dict(response_type="code", client_id=cid, redirect_uri=redirect, code_challenge=chal,
                 code_challenge_method="S256", state="st1", resource="http://127.0.0.1:18080/mcp", scope="whatsapp")
        assert req("GET", "/authorize?" + urllib.parse.urlencode(q))[0] == 200
        assert b"Wrong password" in form("/authorize", dict(q, password="nope"))[2]
        st, h, _ = form("/authorize", dict(q, password=PW))
        loc = urllib.parse.parse_qs(urllib.parse.urlparse(h["Location"]).query)
        assert st == 302 and loc["state"] == ["st1"] and loc["iss"] == ["http://127.0.0.1:18080"]
        tok = dict(grant_type="authorization_code", code=loc["code"][0], client_id=cid, redirect_uri=redirect)
        assert form("/token", dict(tok, code_verifier="wrong" * 10))[0] == 400  # also burns the code
        st, h, _ = form("/authorize", dict(q, password=PW))
        tok["code"] = urllib.parse.parse_qs(urllib.parse.urlparse(h["Location"]).query)["code"][0]
        t = json.loads(form("/token", dict(tok, code_verifier=verifier))[2])
        t2 = json.loads(form("/token", dict(grant_type="refresh_token", refresh_token=t["refresh_token"], client_id=cid))[2])
        assert form("/token", dict(grant_type="refresh_token", refresh_token=t["refresh_token"], client_id=cid))[0] == 400
        auth = {"Authorization": "Bearer " + t2["access_token"], "Content-Type": "application/json"}

        n = [0]
        def rpc(method, params=None):
            n[0] += 1
            return json.loads(req("POST", "/mcp", json.dumps({"jsonrpc": "2.0", "id": n[0], "method": method,
                                                              "params": params or {}}), auth)[2])
        st, h, _ = req("POST", "/mcp", "{}", {"Content-Type": "application/json"})
        assert st == 401 and "resource_metadata" in h["WWW-Authenticate"]
        assert "events" in rpc("initialize", {"protocolVersion": "2025-06-18"})["result"]["capabilities"]
        tools = {t["name"] for t in rpc("tools/list")["result"]["tools"]}
        assert len(tools) == 6 and "whatsapp_resolve_phone" in tools
        assert len(rpc("events/list")["result"]["events"]) == 2

        cb = "http://127.0.0.1:18081/cb"
        sub = {"name": "whatsapp.message.received", "arguments": {"chatIds": ["synthetic:test"]},
               "delivery": {"mode": "webhook", "url": cb, "secret": SECRET}, "cursor": None}
        assert "error" in rpc("events/subscribe", dict(sub, delivery=dict(sub["delivery"], secret="whsec_c2hvcnQ=")))
        assert "error" in rpc("events/subscribe", dict(sub, arguments={"chatIds": ["someone@c.us"]}))
        r1 = rpc("events/subscribe", sub)["result"]
        assert got and got[0]["type"] == "verification"
        r2 = rpc("events/subscribe", sub)["result"]
        assert r1["id"] == r2["id"] and len(got) == 1  # idempotent, verification cached

        # synthetic message -> delivered once, signed; other chats filtered
        py("print(app.ingest({'id':'m1','chat_id':'synthetic:test','sender':'hotel','body':'hello'}))")
        assert wait_for(lambda: len(got) == 2)
        ev = got[1]
        assert ev["name"] == "whatsapp.message.received" and ev["data"]["text"] == "hello" and ev["cursor"]
        assert py("print(app.ingest({'id':'m1','chat_id':'synthetic:test','body':'hello'}))") == "False"
        assert py("print(app.ingest({'id':'m2','chat_id':'blocked@c.us','body':'x'}))") == "False"
        py("app.ingest({'id':'m3','chat_id':'synthetic:quiet','body':'not subscribed'})")
        time.sleep(3)
        assert len(got) == 2

        # transient failure -> retried with same eventId
        fail_next[0] = 1
        py("app.ingest({'id':'m4','chat_id':'synthetic:test','body':'retry me'})")
        assert wait_for(lambda: len(got) == 3, 20) and got[2]["data"]["messageId"] == "m4"

        # send: idempotent, scoped, no event loop on own message
        call = lambda a: rpc("tools/call", {"name": "whatsapp_send_message", "arguments": a})["result"]
        s1 = call({"chatId": "synthetic:test", "text": "ok, when?", "idempotencyKey": "key-00000001"})
        s2 = call({"chatId": "synthetic:test", "text": "ok, when?", "idempotencyKey": "key-00000001"})
        assert s1["structuredContent"]["status"] == "sent" and s2["structuredContent"]["duplicate"] is True
        assert call({"chatId": "synthetic:test", "text": "other", "idempotencyKey": "key-00000001"})["isError"]
        assert call({"chatId": "synthetic:quiet", "text": "x", "idempotencyKey": "key-00000002"})["isError"]
        rd = rpc("tools/call", {"name": "whatsapp_read_chat", "arguments": {"chatId": "synthetic:test"}})["result"]
        assert any(m["fromMe"] for m in rd["structuredContent"]["messages"])
        assert rpc("tools/call", {"name": "whatsapp_read_chat", "arguments": {"chatId": "blocked@c.us"}})["result"]["isError"]
        time.sleep(3)
        assert len(got) == 3

        # WAHA webhook: HMAC enforced
        body = json.dumps({"event": "message", "payload": {"id": "w1", "from": "synthetic:test", "fromMe": False,
                                                           "body": "via waha", "timestamp": int(time.time())}})
        assert req("POST", "/waha/webhook", body, {"X-Webhook-Hmac": "00"})[0] == 401
        sig = hmac.new(HOOK.encode(), body.encode(), hashlib.sha512).hexdigest()
        assert req("POST", "/waha/webhook", body, {"X-Webhook-Hmac": sig})[0] == 200
        assert req("POST", "/waha/webhook", body, {"X-Webhook-Hmac": sig})[0] == 200  # WAHA retry: dedup
        assert wait_for(lambda: len(got) == 4) and got[3]["data"]["messageId"] == "w1"
        time.sleep(2)
        assert len(got) == 4

        # unsubscribe stops delivery; resubscribe with cursor replays the gap
        cursor = got[3]["cursor"]
        assert rpc("events/unsubscribe", {k: sub[k] for k in ("name", "arguments", "delivery")})["result"] == {}
        py("app.ingest({'id':'m5','chat_id':'synthetic:test','body':'while away'})")
        time.sleep(3)
        assert len(got) == 4
        rpc("events/subscribe", dict(sub, cursor=cursor))
        assert wait_for(lambda: len(got) == 5) and got[4]["data"]["messageId"] == "m5"
        # "*" scope: personal chats yes, groups no; reply-only sending
        out = subprocess.run([sys.executable, "-c", """
import app
app.init_db()
assert app.chat_allowed('11111111@c.us') and not app.chat_allowed('g@g.us') and not app.chat_allowed('status@broadcast')
assert not app.chat_allowed('synthetic:nope') and not app.chat_allowed('11111111@c.us/../x')
assert not app.send_allowed('22222222@c.us')
app.ingest({'id':'x1','chat_id':'22222222@c.us','body':'hi'})
assert app.send_allowed('22222222@c.us') and not app.send_allowed('33333333@c.us')
t = app.from_waha({'id':'t1','from':'15550100123@c.us','body':'','_data':{'Info':{'PushName':'',
  'VerifiedName':{'Details':{'verifiedName':'99Food'}}},'Message':{'messageContextInfo':{},'templateMessage':
  {'Format':{'InteractiveMessageTemplate':{'body':{'text':'Retire em 10 min'}}}}}}})
assert t['body'] == 'Retire em 10 min' and t['sender_name'] == '99Food', t
print('star ok')"""], cwd=HERE, env=dict(ENV, ALLOWED_CHATS="*", SEND_CHATS="*",
                     DB_PATH=os.path.join(db_dir, "s.db")), capture_output=True, text=True)
        assert "star ok" in out.stdout, out.stderr
        print("ALL OK")
    finally:
        srv.terminate()
        srv.wait(timeout=5)
        rs.shutdown()
        rs.server_close()


def _up():
    try:
        return req("GET", "/health")[0] == 200
    except OSError:
        return False


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as db_dir:
        main(db_dir)
