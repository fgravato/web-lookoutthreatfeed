"""Tests for the Threat Feed Manager Flask app."""
import configparser
import io
import json
import os
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

# Provide a stub requests module so app.py can be imported without the real one
requests_stub = types.ModuleType("requests")


class _Resp:
    def __init__(self, status_code=200, body=None, text=""):
        self.status_code = status_code
        self._body = body if body is not None else {}
        self.text = text

    def json(self):
        return self._body


requests_stub.get = MagicMock(return_value=_Resp(200, []))
requests_stub.post = MagicMock(return_value=_Resp(200, {"errors": []}))
requests_stub.put = MagicMock(return_value=_Resp(200))
requests_stub.delete = MagicMock(return_value=_Resp(200))
sys.modules.setdefault("requests", requests_stub)

import app as webapp  # noqa: E402


def _reset(mock, return_value):
    """Reset a mock, including side_effect, and restore a default return value."""
    mock.reset_mock(side_effect=True, return_value=True)
    mock.return_value = return_value


class TestLoadApiKey(unittest.TestCase):
    def test_reads_config_ini(self):
        import tempfile
        cfg = configparser.ConfigParser()
        cfg["lookout"] = {"api_key": "test-key-123"}
        orig = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            os.chdir(d)
            with open("config.ini", "w") as f:
                cfg.write(f)
            key = webapp.load_api_key()
            os.chdir(orig)
        self.assertEqual(key, "test-key-123")

    def test_prefers_local_ini(self):
        import tempfile
        orig = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            os.chdir(d)
            for filename, api_key in [("config.ini", "base-key"), ("config.local.ini", "local-key")]:
                cfg = configparser.ConfigParser()
                cfg["lookout"] = {"api_key": api_key}
                with open(filename, "w") as f:
                    cfg.write(f)
            key = webapp.load_api_key()
            os.chdir(orig)
        self.assertEqual(key, "local-key")

    def test_returns_none_when_missing(self):
        import tempfile
        orig = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            os.chdir(d)
            key = webapp.load_api_key()
            os.chdir(orig)
        self.assertIsNone(key)


class _AppTestCase(unittest.TestCase):
    def setUp(self):
        webapp.app.config["TESTING"] = True
        webapp.app.config["SECRET_KEY"] = "test"
        self.client = webapp.app.test_client()
        self.token_patcher = patch.object(webapp, "get_token", return_value="fake-token")
        self.token_patcher.start()
        # Sensible defaults for every test
        _reset(requests_stub.get, _Resp(200, []))
        _reset(requests_stub.post, _Resp(200, {"errors": []}))
        _reset(requests_stub.put, _Resp(200))
        _reset(requests_stub.delete, _Resp(200))

    def tearDown(self):
        self.token_patcher.stop()
        _reset(requests_stub.get, _Resp(200, []))
        _reset(requests_stub.post, _Resp(200, {"errors": []}))
        _reset(requests_stub.put, _Resp(200))
        _reset(requests_stub.delete, _Resp(200))

    def _flash_messages(self):
        """Return flash messages stored in the session without following a redirect."""
        with self.client.session_transaction() as sess:
            return [msg for _cat, msg in sess.get("_flashes", [])]


class TestIndexRoute(_AppTestCase):
    def test_lists_feeds(self):
        guids = ["guid-1"]
        meta = {"feedId": "guid-1", "title": "My Feed Title OK",
                 "description": "Some description here", "feedType": "CSV",
                 "elementsCount": 5, "elementsUploadedAt": "2024-01-01",
                 "allowAnalysis": False}
        requests_stub.get.side_effect = [_Resp(200, guids), _Resp(200, meta)]
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"My Feed Title OK", resp.data)

    def test_empty_feed_list(self):
        # Default return_value is _Resp(200, []) → empty list
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"No feeds found", resp.data)


class TestCreateFeed(_AppTestCase):
    def test_creates_feed(self):
        requests_stub.post.return_value = _Resp(201, {"feedId": "new-guid"})
        # Redirect goes to / — default get.return_value gives empty feed list
        resp = self.client.post("/feeds/create", data={
            "title": "My New Feed Title",
            "description": "A useful description here",
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Feed created", resp.data)

    def test_title_too_short(self):
        resp = self.client.post("/feeds/create", data={
            "title": "short",
            "description": "A useful description here",
        }, follow_redirects=True)
        self.assertIn(b"8", resp.data)  # validation message references 8–255

    def test_title_too_long(self):
        resp = self.client.post("/feeds/create", data={
            "title": "x" * 256,
            "description": "A useful description here",
        }, follow_redirects=True)
        self.assertIn(b"255", resp.data)


class TestFeedDetail(_AppTestCase):
    def _meta(self):
        return {"feedId": "guid-1", "title": "Feed One Title OK",
                "description": "Desc here too", "feedType": "CSV",
                "elementsCount": 2, "elementsUploadedAt": None, "allowAnalysis": False}

    def test_shows_domains(self):
        csv_body = "domain\nexample.com\nevil.net\n"
        requests_stub.get.side_effect = [_Resp(200, self._meta()), _Resp(200, text=csv_body)]
        resp = self.client.get("/feeds/guid-1")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"example.com", resp.data)
        self.assertIn(b"evil.net", resp.data)

    def test_search_filters_domains(self):
        csv_body = "domain\nexample.com\nevil.net\n"
        requests_stub.get.side_effect = [_Resp(200, self._meta()), _Resp(200, text=csv_body)]
        resp = self.client.get("/feeds/guid-1?q=evil")
        self.assertIn(b"evil.net", resp.data)
        # Only evil.net should appear as a delete-button hidden value (domain row),
        # not example.com which was filtered out. The placeholder may contain "example.com".
        self.assertNotIn(b'value="example.com"', resp.data)


class TestDomainOps(_AppTestCase):
    def test_add_domains(self):
        resp = self.client.post("/feeds/guid-1/domains/add",
                                data={"domains": "bad.com\nnasty.org"},
                                follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        call_args = requests_stub.post.call_args
        payload = call_args.kwargs.get("json") or call_args[1].get("json", {})
        self.assertEqual(len(payload["operations"]), 2)
        self.assertEqual(payload["operations"][0]["action"], "add")

    def test_delete_domains(self):
        resp = self.client.post("/feeds/guid-1/domains/delete",
                                data={"domains": "bad.com"},
                                follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        call_args = requests_stub.post.call_args
        payload = call_args.kwargs.get("json") or call_args[1].get("json", {})
        self.assertEqual(payload["operations"][0]["action"], "delete")

    def test_add_empty_domains(self):
        resp = self.client.post("/feeds/guid-1/domains/add",
                                data={"domains": ""},
                                follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        msgs = self._flash_messages()
        self.assertTrue(any("No domains" in m for m in msgs))

    def test_bulk_limit_enforced(self):
        domains = "\n".join(f"dom{i}.com" for i in range(15001))
        resp = self.client.post("/feeds/guid-1/domains/add",
                                data={"domains": domains},
                                follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        msgs = self._flash_messages()
        self.assertTrue(any("15,000" in m for m in msgs))


class TestFileUpload(_AppTestCase):
    def test_csv_upload(self):
        requests_stub.post.return_value = _Resp(
            200, text='"ROW_NUMBER","DOMAIN","ACTION","ERROR_CODE","ERROR_MESSAGE"\n')
        data = {"uploadType": "INCREMENTAL",
                "file": (io.BytesIO(b"domain,action\nbad.com,add\n"), "upload.csv")}
        resp = self.client.post("/feeds/guid-1/domains/upload",
                                data=data, content_type="multipart/form-data",
                                follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        msgs = self._flash_messages()
        self.assertTrue(any("successful" in m for m in msgs))

    def test_json_upload(self):
        payload = json.dumps({"operations": [{"domain": "bad.com", "action": "add"}]}).encode()
        data = {"uploadType": "INCREMENTAL",
                "file": (io.BytesIO(payload), "upload.json")}
        resp = self.client.post("/feeds/guid-1/domains/upload",
                                data=data, content_type="multipart/form-data",
                                follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        msgs = self._flash_messages()
        self.assertTrue(any("Processed" in m for m in msgs))

    def test_invalid_file_type(self):
        data = {"uploadType": "INCREMENTAL",
                "file": (io.BytesIO(b"junk"), "upload.txt")}
        resp = self.client.post("/feeds/guid-1/domains/upload",
                                data=data, content_type="multipart/form-data",
                                follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        msgs = self._flash_messages()
        self.assertTrue(any(".csv and .json" in m for m in msgs))

    def test_invalid_json(self):
        data = {"uploadType": "INCREMENTAL",
                "file": (io.BytesIO(b"not json"), "upload.json")}
        resp = self.client.post("/feeds/guid-1/domains/upload",
                                data=data, content_type="multipart/form-data",
                                follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        msgs = self._flash_messages()
        self.assertTrue(any("Invalid JSON" in m for m in msgs))


class TestDeleteFeed(_AppTestCase):
    def test_delete_redirects(self):
        resp = self.client.post("/feeds/guid-1/delete")
        self.assertEqual(resp.status_code, 302)

    def test_delete_api_error(self):
        requests_stub.delete.return_value = _Resp(404, {"detail": "Feed not found"})
        # Redirect goes to / — default get.return_value gives empty feed list
        resp = self.client.post("/feeds/guid-1/delete", follow_redirects=True)
        self.assertIn(b"Delete failed", resp.data)


class TestUpdateFeed(_AppTestCase):
    def test_update_feed(self):
        meta = {"feedId": "guid-1", "title": "Updated Title OK",
                "description": "New description here", "feedType": "CSV",
                "elementsCount": 0, "elementsUploadedAt": None, "allowAnalysis": False}
        requests_stub.get.side_effect = [_Resp(200, meta), _Resp(200, text="domain\n")]
        resp = self.client.post("/feeds/guid-1/update", data={
            "title": "Updated Title OK",
            "description": "New description here",
        }, follow_redirects=True)
        self.assertIn(b"Feed updated", resp.data)


if __name__ == "__main__":
    unittest.main()
