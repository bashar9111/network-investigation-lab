import copy, io, json, pathlib, sys, unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import engine, app

class InvestigationTests(unittest.TestCase):
    def setUp(self): self.rows=engine.demo_rows()
    def test_synthetic_scenario_has_four_explainable_signals(self):
        c=engine.analyze(self.rows,synthetic=True)
        self.assertEqual({x["rule"] for x in c["alerts"]},set(engine.RULES))
        self.assertEqual(c["metrics"]["events"],252)
        self.assertTrue(all(a["evidence"] and a["threshold"] and a["next_steps"] for a in c["alerts"]))
    def test_normal_baseline_has_no_alerts(self):
        r=[x for x in self.rows if x["src"]=="192.0.2.10"]
        self.assertEqual(engine.analyze(r)["alerts"],[])
    def test_port_sweep_requires_distinct_ports(self):
        rows=[copy.copy(r) for r in self.rows if r["syn"]]
        for r in rows:r["port"]=443
        self.assertEqual(engine.analyze(rows)["alerts"],[])
    def test_port_window_does_not_combine_separate_minutes(self):
        rows=[copy.copy(r) for r in self.rows if r["syn"]]
        for i,r in enumerate(rows):r["timestamp"]=1000+i*70
        self.assertEqual(engine.analyze(rows)["alerts"],[])
    def test_port_threshold_boundary(self):
        rows=[r for r in self.rows if r["syn"]]
        self.assertFalse(engine.analyze(rows[:11])["alerts"])
        self.assertEqual(engine.analyze(rows[:12])["alerts"][0]["rule"],"TCP-SCAN")
    def test_dns_response_not_counted_as_query(self):
        c=engine.analyze(self.rows)
        self.assertEqual(c["metrics"]["dns_queries"],132)
    def test_nxdomain_attributes_client_not_resolver(self):
        a=next(a for a in engine.analyze(self.rows)["alerts"] if a["rule"]=="DNS-NXDOMAIN")
        self.assertEqual(a["subject"],"192.0.2.80")
    def test_nxdomain_minimum_sample(self):
        r=[x for x in self.rows if x["response"]][:19]
        self.assertEqual(engine.analyze(r)["alerts"],[])
    def test_long_labels_need_repetition(self):
        r=[x for x in self.rows if x["src"]=="192.0.2.90"][:7]
        self.assertEqual(engine.analyze(r)["alerts"],[])
    def test_csv_round_trip_preserves_signals(self):
        rows=engine.parse_csv(engine.csv_bytes(self.rows).decode())
        self.assertEqual({a["rule"] for a in engine.analyze(rows)["alerts"]},set(engine.RULES))
    def test_missing_csv_header_rejected(self):
        with self.assertRaises(ValueError):engine.parse_csv("wrong,columns\n1,2")
    def test_empty_csv_rejected(self):
        with self.assertRaises(ValueError):engine.parse_csv("timestamp,src\n")
    def test_nan_does_not_enter_metrics(self):
        rows=engine.parse_csv("timestamp,src,length\n1,192.0.2.10,nan")
        self.assertEqual(engine.analyze(rows)["metrics"]["bytes"],0)
    def test_out_of_range_timestamp_rejected(self):
        with self.assertRaises(ValueError):engine.parse_csv("timestamp,src\n999999999999999,192.0.2.10")
    def test_different_evidence_gets_different_case_id(self):
        changed=copy.deepcopy(self.rows);changed[0]["domain"]="changed.example"
        self.assertNotEqual(engine.analyze(self.rows)["id"],engine.analyze(changed)["id"])
    def test_pihole_query_block_matching(self):
        rows=engine.parse_pihole((engine.ROOT/"samples/pihole.log").read_text())
        c=engine.analyze(rows)
        self.assertEqual(c["metrics"]["dns_queries"],48)
        self.assertEqual(c["metrics"]["blocked"],16)
    def test_unsupported_log_rejected(self):
        with self.assertRaises(ValueError):engine.parse_pihole("not a query")
    def test_external_payload_has_no_network_identity(self):
        case=engine.analyze(self.rows,source="company-confidential.pcap")
        payload=json.dumps(engine.external_summary(case))
        for bad in ["192.0.2.","198.51.100.","example","invalid","company-confidential",'"evidence":','"subject":']:
            self.assertNotIn(bad,payload)
    def test_report_escapes_untrusted_input(self):
        case=engine.analyze(self.rows,source='<script>alert("x")</script>')
        case["alerts"][0]["evidence"][0]["detail"]="<img src=x onerror=alert(1)>"
        output=app.case_report(case)
        self.assertNotIn("<script>",output);self.assertNotIn("<img ",output)
        self.assertIn("&lt;script&gt;",output)
    def test_no_key_requires_offline_fallback(self):
        with patch.dict(app.os.environ,{},clear=True):
            with self.assertRaises(ValueError):app.ai_brief(engine.analyze(self.rows))
    def test_workflow_is_inactive_and_has_no_credentials(self):
        wf=json.loads((engine.ROOT/"integrations/n8n-workflow.json").read_text())
        self.assertFalse(wf["active"])
        self.assertTrue(all("credentials" not in node for node in wf["nodes"]))
        self.assertIn("CONFIGURE_MODEL",json.dumps(wf))
    @unittest.skipUnless(engine.tshark_path(),"TShark not installed")
    def test_real_pcap_decoding_reproduces_all_rules(self):
        rows=engine.read_capture((engine.ROOT/"samples/training-scenario.pcap").read_bytes(),".pcap")
        case=engine.analyze(rows)
        self.assertEqual(case["metrics"]["events"],252)
        self.assertEqual({a["rule"] for a in case["alerts"]},set(engine.RULES))
    @unittest.skipUnless(engine.tshark_path(),"TShark not installed")
    def test_corrupt_pcap_rejected(self):
        with self.assertRaises(ValueError):engine.read_capture(b"invalid capture",".pcap")

if __name__=="__main__":unittest.main(verbosity=2)

