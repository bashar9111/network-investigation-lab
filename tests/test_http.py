import io, json, pathlib, re, ssl, sys, threading, unittest, urllib.request, urllib.error
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import app, engine

class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=app.http.server.ThreadingHTTPServer(("127.0.0.1",0),app.Handler)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.base=f"http://127.0.0.1:{cls.server.server_port}"
        cls.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)))
    @classmethod
    def tearDownClass(cls):cls.server.shutdown();cls.server.server_close()
    def req(self,path,data=None,token=True,headers=None):
        h={"Content-Type":"application/json"}
        if token:h["X-Lab-Token"]=app.TOKEN
        h.update(headers or {})
        if isinstance(data,dict):data=json.dumps(data).encode()
        return self.opener.open(urllib.request.Request(self.base+path,data=data,headers=h),timeout=10)
    def case(self):
        with self.req("/api/demo") as r:return json.load(r)
    def test_root_and_assets(self):
        with self.req("/") as r:
            text=r.read().decode();self.assertIn("Network Investigation Lab",text);self.assertNotIn("__TOKEN__",text)
        with self.req("/app.js") as r:self.assertEqual(r.status,200)
    def test_unknown_route(self):
        with self.assertRaises(urllib.error.HTTPError) as e:self.req("/../../app.py")
        self.assertEqual(e.exception.code,404)
    def test_no_token_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as e:self.req("/api/brief",{"case_id":"x"},token=False)
        self.assertEqual(e.exception.code,403)
    def test_wrong_origin_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as e:self.req("/api/brief",{"case_id":"x"},headers={"Origin":"https://untrusted.invalid"})
        self.assertEqual(e.exception.code,403)
    def test_csv_upload_and_analyst_decision(self):
        with self.req("/api/analyze",engine.csv_bytes(engine.demo_rows()),headers={"X-Filename":"training.csv","Content-Type":"application/octet-stream"}) as r:
            c=json.load(r);self.assertFalse(c["synthetic"]);self.assertEqual(c["metrics"]["alerts"],4)
        with self.req("/api/triage",{"case_id":c["id"],"alert_id":"AL-001","status":"Benign"}) as r:
            self.assertEqual(json.load(r)["alerts"][0]["status"],"Benign")
    def test_bad_upload_returns_useful_error(self):
        with self.assertRaises(urllib.error.HTTPError) as e:self.req("/api/analyze",b"bad,input\n1,2",headers={"X-Filename":"bad.csv"})
        self.assertEqual(e.exception.code,400);self.assertIn("timestamp",e.exception.read().decode())
    def test_html_json_and_eml_exports(self):
        c=self.case()
        for fmt in ("html","json","eml"):
            with self.req("/api/report",{"case_id":c["id"],"format":fmt}) as r:
                body=r.read();self.assertGreater(len(body),100);self.assertIn("attachment",r.headers["Content-Disposition"])
                if fmt=="eml":self.assertIn(b"X-Unsent: 1",body)
    def test_offline_brief_does_not_need_network(self):
        c=self.case()
        with patch.object(app.urllib.request,"urlopen",side_effect=AssertionError("Unexpected external call")):
            with self.req("/api/brief",{"case_id":c["id"],"live":False}) as r:
                self.assertFalse(json.load(r)["live"])
    def test_ai_requires_explicit_confirmation(self):
        c=self.case()
        with self.assertRaises(urllib.error.HTTPError) as e:self.req("/api/brief",{"case_id":c["id"],"live":True})
        self.assertEqual(e.exception.code,400)
    def test_webhook_requires_explicit_confirmation(self):
        c=self.case()
        with self.assertRaises(urllib.error.HTTPError) as e:self.req("/api/webhook",{"case_id":c["id"]})
        self.assertEqual(e.exception.code,400)
    def test_mocked_openai_adapter_minimizes_payload(self):
        c=self.case();captured={}
        def fake(req,timeout,**kwargs):
            captured["data"]=json.loads(req.data)
            return io.BytesIO(json.dumps({"output":[{"content":[{"type":"output_text","text":"Review the evidence."}]}]}).encode())
        with patch.dict(app.os.environ,{"OPENAI_API_KEY":"test-only-fake-key","OPENAI_MODEL":"test-only-model"}):
            with patch.object(app.urllib.request,"urlopen",side_effect=fake):
                self.assertEqual(app.ai_brief(c),"Review the evidence.")
        self.assertFalse(captured["data"]["store"])
        self.assertNotIn("192.0.2.",json.dumps(captured["data"]))
        self.assertNotIn("domain",captured["data"]["input"])
    def test_mocked_webhook_sends_aggregate_only(self):
        c=self.case();captured={}
        class Response(io.BytesIO):status=200
        def fake(req,timeout,**kwargs):captured["body"]=json.loads(req.data);return Response(b"ok")
        with patch.dict(app.os.environ,{"N8N_WEBHOOK_URL":"https://automation.example/webhook/test","N8N_WEBHOOK_TOKEN":"test-only-secret"}):
            with patch.object(app.urllib.request,"urlopen",side_effect=fake):
                with self.req("/api/webhook",{"case_id":c["id"],"confirm":True}) as r:self.assertIn("delivered",json.load(r)["message"])
        self.assertNotIn("192.0.2.",json.dumps(captured["body"]))
    def test_malformed_json_returns_400(self):
        with self.assertRaises(urllib.error.HTTPError) as e:self.req("/api/brief",b"{")
        self.assertEqual(e.exception.code,400)

if __name__=="__main__":unittest.main(verbosity=2)

