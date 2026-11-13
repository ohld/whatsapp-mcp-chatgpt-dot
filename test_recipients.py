"""First-contact MCP checks with a stub WAHA and a disposable bridge database."""

import os
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlsplit

import app


PHONE = "+12025550100"
CHAT = "123456789012345@lid"
MESSAGE = "Is a table for two available?"


class RecipientsTest(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(patch.multiple(
            app, _local=threading.local(), DB_PATH=os.path.join(directory, "bridge.db"),
            ALLOWED=["*"], ALL_CHATS=True, SEND_CHATS=["*"], SEND_ENABLED=True,
            SEND_NEW_CHATS=True, SEND_DAILY_CAP=30, WAHA_SESSION="default",
        ))
        self.lookup = {"numberExists": True, "chatId": CHAT}
        self.send_error = None
        self.history = []
        self.requests = []
        self.enterContext(patch.object(app, "waha", side_effect=self.fake_waha))
        app.init_db()
        self.addCleanup(app.db().close)

    def fake_waha(self, method, path, body=None, timeout=20):
        url = urlsplit(path)
        self.requests.append((method, url.path, body))
        if method == "GET" and url.path == "/api/contacts/check-exists":
            self.assertEqual(parse_qs(url.query), {"phone": ["12025550100"], "session": ["default"]})
            if isinstance(self.lookup, Exception):
                raise self.lookup
            return self.lookup
        if method == "POST" and url.path == "/api/sendText":
            if self.send_error is not None:
                raise self.send_error
            return {"id": "first-message"}
        if method == "GET" and unquote(url.path) == f"/api/default/chats/{CHAT}/messages":
            return self.history
        self.fail(f"unexpected WAHA request: {method} {url.path}")

    def call(self, name, **arguments):
        return app.rpc({"method": "tools/call", "params": {"name": name, "arguments": arguments}}, "owner")

    def send(self, chat=PHONE, key="new-contact-1"):
        return self.call("whatsapp_send_message", chatId=chat, text=MESSAGE, idempotencyKey=key)

    def posts(self):
        return [body for method, path, body in self.requests if method == "POST" and path == "/api/sendText"]

    def test_first_contact_resolves_then_sends_once(self):
        self.assertIs(self.call("whatsapp_status")["structuredContent"]["new_chats_enabled"], True)
        resolved = self.call("whatsapp_resolve_phone", phoneNumber="+1 (202) 555-0100")["structuredContent"]
        self.assertEqual(resolved["phoneNumber"], PHONE)
        self.assertIs(resolved["numberExists"], True)
        self.assertEqual(resolved["chatId"], CHAT)
        self.assertIs(resolved["sendAllowed"], True)
        self.assertEqual(self.posts(), [])

        first = self.send()["structuredContent"]
        self.assertEqual((first["status"], first["messageId"]), ("sent", "first-message"))
        second = self.send()["structuredContent"]
        self.assertIs(second["duplicate"], True)
        self.assertEqual(second["messageId"], first["messageId"])
        self.assertEqual(self.posts(), [
            {"session": "default", "chatId": CHAT, "text": MESSAGE},
        ])

    def test_retry_reconciles_unknown_first_send_without_second_post(self):
        self.send_error = TimeoutError("acknowledgment lost")
        self.assertEqual(self.send()["structuredContent"]["status"], "unknown")
        self.history = [{"id": "first-message", "fromMe": True, "body": MESSAGE, "timestamp": app.now()}]

        retried = self.send()["structuredContent"]
        self.assertEqual(retried["status"], "sent")
        self.assertEqual(retried["messageId"], "first-message")
        self.assertIs(retried["reconciled"], True)
        self.assertEqual(len(self.posts()), 1)

    def test_default_scope_still_needs_history(self):
        with patch.object(app, "SEND_NEW_CHATS", False):
            self.assertIs(self.call("whatsapp_status")["structuredContent"]["new_chats_enabled"], False)
            resolved = self.call("whatsapp_resolve_phone", phoneNumber=PHONE)["structuredContent"]
            self.assertIs(resolved["sendAllowed"], False)
            self.assertTrue(self.send()["isError"])
            self.assertEqual(self.posts(), [])
            app.ingest({"id": "prior", "chat_id": CHAT, "body": "hello"})
            self.assertEqual(self.send(CHAT)["structuredContent"]["status"], "sent")

    def test_invalid_phone_is_rejected_before_provider_request(self):
        for number in (
            "12025550100", "11 99999-9999", "https://wa.me/12025550100", "\uff0b12025550100",
            "+0 2025550100", "+1 2025550100 ext 2", "+1\u0662\u0660\u0662 5550100",
            "+1", "+1234567890123456",
        ):
            with self.subTest(number=number):
                self.assertTrue(self.call("whatsapp_resolve_phone", phoneNumber=number)["isError"])
                self.assertTrue(self.send(number)["isError"])
        self.assertEqual(self.requests, [])

    def test_unregistered_number_never_sends(self):
        self.lookup = {"numberExists": False}
        resolved = self.call("whatsapp_resolve_phone", phoneNumber=PHONE)["structuredContent"]
        self.assertIs(resolved["numberExists"], False)
        self.assertNotIn("chatId", resolved)
        self.assertTrue(self.send()["isError"])
        self.assertEqual(self.posts(), [])

    def test_bad_provider_response_never_sends(self):
        for result in (
            RuntimeError("private provider detail"),
            {"numberExists": "true", "chatId": CHAT},
            {"numberExists": True, "chatId": "12345@g.us"},
            {"numberExists": True, "chatId": None},
        ):
            with self.subTest(result=result):
                self.lookup = result
                response = self.send()
                self.assertTrue(response["isError"])
                self.assertNotIn("private provider detail", response["structuredContent"]["error"])
        self.assertEqual(self.posts(), [])

    def test_wildcard_does_not_send_to_non_personal_chats(self):
        with patch.object(app, "ALLOWED", ["*", "synthetic:read-only"]):
            for chat in ("12345@g.us", "status@broadcast", "12345@newsletter", "synthetic:read-only", "synthetic:unknown"):
                with self.subTest(chat=chat):
                    self.assertTrue(self.send(chat)["isError"])
        self.assertEqual(self.posts(), [])

    def test_send_and_read_allowlists_still_apply(self):
        with patch.object(app, "SEND_CHATS", ["12025550101@c.us"]):
            self.assertTrue(self.send()["isError"])
        with patch.multiple(app, ALL_CHATS=False, ALLOWED=["12025550100@c.us"]):
            self.assertTrue(self.send()["isError"])  # the provider returned a LID outside the allowlist
        self.assertEqual(self.posts(), [])

    def test_finite_read_scope_cannot_probe_unallowed_numbers(self):
        with patch.multiple(app, ALL_CHATS=False, ALLOWED=["12025550101@c.us"]):
            self.assertTrue(self.call("whatsapp_resolve_phone", phoneNumber=PHONE)["isError"])
            self.assertTrue(self.send()["isError"])
        self.assertEqual(self.requests, [])

    def test_send_disabled_and_daily_cap_still_apply(self):
        with patch.object(app, "SEND_ENABLED", False):
            self.assertTrue(self.send()["isError"])
            self.assertEqual(self.requests, [])
        with patch.object(app, "SEND_DAILY_CAP", 1):
            self.assertEqual(self.send()["structuredContent"]["status"], "sent")
            self.assertTrue(self.send(key="new-contact-2")["isError"])
        self.assertEqual(len(self.posts()), 1)


if __name__ == "__main__":
    unittest.main()
