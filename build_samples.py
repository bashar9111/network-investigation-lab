"""Generate synthetic, shareable fixtures and a credential-free n8n workflow."""
import json, pathlib, socket, struct
from engine import ROOT, demo_rows, csv_bytes
rows=demo_rows()
(ROOT/"samples/network-events.csv").write_bytes(csv_bytes(rows))
def checksum(data):
    if len(data)%2: data+=b"\0"
    s=sum(struct.unpack("!%dH"%(len(data)//2),data))
    s=(s>>16)+(s&65535);s+=(s>>16)
    return (~s)&65535
def packet(row):
    src=socket.inet_aton(row["src"]);dst=socket.inet_aton(row["dst"])
    if row["domain"]:
        name=b"".join(bytes([len(x)])+x.encode() for x in row["domain"].split("."))+b"\0"
        dns=struct.pack("!HHHHHH",row["frame"],0x8183 if row["response"] else 0x0100,1,0,0,0)+name+struct.pack("!HH",1,1)
        transport=struct.pack("!HHHH",53 if row["response"] else 40000+row["frame"],40000+row["frame"]-1 if row["response"] else 53,len(dns)+8,0)+dns
        proto=17
    else:
        proto=6;payload=b"" if row["syn"] else b"synthetic-training-payload"
        segment=struct.pack("!HHIIBBHHH",40000,row["port"],row["frame"],0,5<<4,2 if row["syn"] else 0x18,65535,0,0)+payload
        check=checksum(src+dst+struct.pack("!BBH",0,6,len(segment))+segment)
        transport=segment[:16]+struct.pack("!H",check)+segment[18:]
    ip=struct.pack("!BBHHHBBH4s4s",0x45,0,20+len(transport),row["frame"],0,64,proto,0,src,dst)
    ip=ip[:10]+struct.pack("!H",checksum(ip))+ip[12:]
    return bytes.fromhex("0200000000020200000000010800")+ip+transport
pcap=bytearray(struct.pack("<IHHIIII",0xa1b2c3d4,2,4,0,0,65535,1))
for r in rows:
    frame=packet(r); sec=int(r["timestamp"]);usec=int((r["timestamp"]-sec)*1e6)
    pcap+=struct.pack("<IIII",sec,usec,len(frame),len(frame))+frame
(ROOT/"samples/training-scenario.pcap").write_bytes(pcap)
logs=[]
for i in range(48):
    logs.append(f"Aug  3 10:00:{i:02} dnsmasq[100]: query[A] telemetry-{i}.example from 192.0.2.80")
    if i%3==0:logs.append(f"Aug  3 10:00:{i:02} dnsmasq[100]: gravity telemetry-{i}.example is 0.0.0.0")
(ROOT/"samples/pihole.log").write_text("\n".join(logs)+"\n",encoding="utf-8")

guard="""const b=$json.body;
if (!b || !/^CASE-[A-F0-9]{8}$/.test(b.case_id)) throw new Error('Invalid case');
const metrics={};
for (const k of ['events','bytes','duration','hosts','dns_queries','blocked','high','alerts']) {
 const v=Number(b.metrics?.[k]); if (!Number.isFinite(v)||v<0) throw new Error('Invalid metrics'); metrics[k]=v;
}
const allowed=['TCP-SCAN','DNS-BURST','DNS-NXDOMAIN','DNS-LONG'];
const findings=(b.findings||[]).slice(0,100).map(f=>{
 if (!allowed.includes(f.rule)||!['High','Medium','Low'].includes(f.severity)) throw new Error('Invalid rule');
 return {rule:f.rule,severity:f.severity};
});
return [{json:{case_id:b.case_id,synthetic:b.synthetic===true,metrics,findings}}];"""
wf=dict(name="Network Lab — Reviewed Aggregate to OpenAI and Email",active=False,settings={"executionOrder":"v1"},
 nodes=[
 dict(id="webhook",name="Aggregate Webhook",type="n8n-nodes-base.webhook",typeVersion=2,position=[0,0],
      parameters={"httpMethod":"POST","path":"network-lab-reviewed-brief","authentication":"headerAuth","responseMode":"onReceived","options":{}}),
 dict(id="minimize",name="Validate and Minimize",type="n8n-nodes-base.code",typeVersion=2,position=[240,0],parameters={"jsCode":guard}),
 dict(id="openai",name="OpenAI Brief",type="n8n-nodes-base.httpRequest",typeVersion=4.2,position=[480,0],
      parameters={"method":"POST","url":"https://api.openai.com/v1/responses","authentication":"genericCredentialType",
       "genericAuthType":"httpHeaderAuth","sendBody":True,"specifyBody":"json",
       "jsonBody":"={{ JSON.stringify({model: 'CONFIGURE_MODEL', store: false, max_output_tokens: 700, instructions: 'You assist a defensive analyst. Summarize only the supplied counts and heuristic rules. Do not invent incidents or evidence. State uncertainty and review steps. Do not recommend automatic blocking.', input: JSON.stringify($json)}) }}",
       "options":{"timeout":45000}}),
 dict(id="email",name="Send Reviewed Brief",type="n8n-nodes-base.emailSend",typeVersion=2.1,position=[720,0],
      parameters={"fromEmail":"sender@example.invalid","toEmail":"recipient@example.invalid","subject":"Network lab — analyst review",
       "emailFormat":"text","text":"={{ ($json.output || []).flatMap(item => item.content || []).filter(part => part.type === 'output_text').map(part => part.text).join('\\n') || 'No AI text returned. Inspect this workflow execution before taking action.' }}",
       "options":{}}),
 dict(id="note",name="Setup before activation",type="n8n-nodes-base.stickyNote",typeVersion=1,position=[0,-300],
      parameters={"content":"## Inactive setup template — review before use\n1. Configure Webhook Header Auth: X-Lab-Webhook-Token with your own secret.\n2. Configure OpenAI HTTP Header Auth: Authorization = Bearer YOUR_KEY (in credentials only).\n3. Replace CONFIGURE_MODEL with an available model ID.\n4. Configure SMTP credentials, sender and your own test recipient.\n5. Test with synthetic data, inspect output, then activate only when ready.\nWebhook acceptance does not prove email delivery. No credentials are included.","height":240,"width":850})
 ],
 connections={
 "Aggregate Webhook":{"main":[[{"node":"Validate and Minimize","type":"main","index":0}]]},
 "Validate and Minimize":{"main":[[{"node":"OpenAI Brief","type":"main","index":0}]]},
 "OpenAI Brief":{"main":[[{"node":"Send Reviewed Brief","type":"main","index":0}]]}
 },pinData={},tags=[])
(ROOT/"integrations/n8n-workflow.json").write_text(json.dumps(wf,indent=2),encoding="utf-8")
print("Generated synthetic CSV, PCAP, Pi-hole log and inactive n8n workflow.")

