"""Offline network investigation engine. Standard library only."""
import csv, io, json, math, collections, datetime, hashlib, os, pathlib, re, shutil, subprocess, tempfile

ROOT = pathlib.Path(__file__).resolve().parent
MAX_ROWS = 100000
FIELDS = ["frame.number","frame.time_epoch","ip.src","ipv6.src","ip.dst","ipv6.dst","frame.protocols","frame.len","tcp.dstport","tcp.flags.syn","tcp.flags.ack","dns.qry.name","dns.flags.response","dns.flags.rcode"]

def tshark_path():
    return shutil.which("tshark") or (r"C:\Program Files\Wireshark\tshark.exe" if pathlib.Path(r"C:\Program Files\Wireshark\tshark.exe").exists() else None)

def read_capture(data, suffix):
    executable = tshark_path()
    if not executable:
        raise ValueError("Wireshark/TShark is required for PCAP files. CSV and demo mode work without it.")
    with tempfile.TemporaryDirectory(prefix="network-lab-") as tmp:
        path = pathlib.Path(tmp) / ("capture" + suffix)
        path.write_bytes(data)
        args = [executable,"-n","-r",str(path),"-c",str(MAX_ROWS),"-T","fields","-E","header=y","-E","separator=,","-E","quote=d","-E","occurrence=f"]
        for field in FIELDS:
            args += ["-e",field]
        try:
            result = subprocess.run(args,capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=45)
        except subprocess.TimeoutExpired:
            raise ValueError("Capture analysis exceeded 45 seconds. Try a smaller file.")
        if result.returncode:
            raise ValueError("The capture could not be decoded. Please use a valid PCAP or PCAPNG file.")
        return parse_csv(result.stdout, tshark=True)

def number(value, fallback=0):
    try:
        n=float(value)
        return n if math.isfinite(n) else fallback
    except (TypeError,ValueError):
        return fallback

def parse_time(value):
    try:
        return datetime.datetime.fromisoformat(str(value).replace("Z","+00:00")).timestamp()
    except (ValueError,TypeError):
        return number(value)

def parse_csv(text, tshark=False):
    reader=csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ValueError("CSV needs a header row.")
    if not tshark and not {"timestamp","src"}.issubset(reader.fieldnames):
        raise ValueError("CSV must include timestamp and src. See the sample CSV for optional columns.")
    rows=[]
    for i, r in enumerate(reader):
        if i >= MAX_ROWS:
            raise ValueError("CSV is limited to 100,000 events.")
        if tshark:
            row=dict(timestamp=number(r.get("frame.time_epoch")),src=r.get("ip.src") or r.get("ipv6.src") or "unknown",
                     dst=r.get("ip.dst") or r.get("ipv6.dst") or "unknown",protocol=(r.get("frame.protocols") or "OTHER").split(":")[-1].upper(),
                     length=number(r.get("frame.len")),port=int(number(r.get("tcp.dstport"))),
                     syn=str(r.get("tcp.flags.syn","")).lower() in ("1","true") and str(r.get("tcp.flags.ack","")).lower() not in ("1","true"),
                     domain=r.get("dns.qry.name") or "",response=str(r.get("dns.flags.response","")).lower() in ("1","true"),
                     rcode=int(number(r.get("dns.flags.rcode"))),blocked=False,frame=int(number(r.get("frame.number"),i+1)))
        else:
            row=dict(timestamp=parse_time(r.get("timestamp")),src=r.get("src","unknown"),dst=r.get("dst","unknown"),
                     protocol=r.get("protocol","DNS" if r.get("domain") else "OTHER").upper(),
                     length=number(r.get("length")),port=int(number(r.get("port"))),
                     syn=str(r.get("syn","")).lower() in ("1","true"),
                     domain=r.get("domain","").strip().rstrip(".").lower(),
                     response=str(r.get("response","")).lower() in ("1","true"),
                     rcode=int(number(r.get("rcode"))),blocked=str(r.get("blocked","")).lower() in ("1","true"),
                     frame=i+1)
        if not 0<=row["timestamp"]<=4102444800:
            raise ValueError("Event timestamps must be between 1970 and 2100.")
        row["length"]=max(0,row["length"])
        if any(len(str(row[k]))>512 for k in ("src","dst","protocol","domain")):
            raise ValueError("An event field exceeds 512 characters.")
        rows.append(row)
    if not rows:
        raise ValueError("No decodable events were found.")
    return rows

def parse_pihole(text):
    # Supported native dnsmasq query lines and adjacent blocked/gravity responses.
    rows=[]
    lookup={}
    for line in text.splitlines():
        m=re.search(r"query\[[^\]]+\]\s+(\S+)\s+from\s+(\S+)",line)
        if m:
            prefix=line[:15]
            try:
                ts=datetime.datetime.strptime(str(datetime.datetime.now().year)+" "+prefix,"%Y %b %d %H:%M:%S").timestamp()
            except ValueError:
                raise ValueError("Pi-hole log lines must begin with 'Mon DD HH:MM:SS'.")
            rows.append(dict(timestamp=ts,src=m[2],dst="DNS resolver",protocol="DNS",length=0,port=53,syn=False,
                             domain=m[1].lower().rstrip("."),response=False,rcode=0,blocked=False,frame=len(rows)+1))
            lookup[m[1].lower().rstrip(".")]=rows[-1]
        b=re.search(r"(?:gravity|blacklisted|regex(?: blacklisted)?)\s+(\S+)\s+is\s+",line)
        if b and b[1].lower().rstrip(".") in lookup:
            lookup[b[1].lower().rstrip(".")]["blocked"]=True
        if len(rows)>MAX_ROWS:
            raise ValueError("Log is limited to 100,000 queries.")
    if not rows:
        raise ValueError("No supported Pi-hole query lines found. Use the sample log format or normalized CSV.")
    return rows

def demo_rows():
    rows=[]
    start=1785751200
    def add(offset,src,dst="192.0.2.53",protocol="DNS",domain="",**kw):
        row=dict(timestamp=start+offset,src=src,dst=dst,protocol=protocol,domain=domain,length=84,port=53,syn=False,response=False,rcode=0,blocked=False,frame=len(rows)+1)
        row.update(kw); rows.append(row)
    for i in range(72):
        add(i*2.2,"192.0.2.10",domain=["docs.example","updates.example","mail.example"][i%3])
    for i in range(24):
        add(20+i*.5,"192.0.2.40",dst="198.51.100.20",protocol="TCP",port=20+i,syn=True,domain="",length=60)
    for i in range(96):
        add(60+i*.3,"192.0.2.53" if i%2 else "192.0.2.80",dst="192.0.2.80" if i%2 else "192.0.2.53",domain=f"missing-{i//2}.invalid",response=i%2==1,rcode=3 if i%2 else 0,blocked=i%4==0)
    for i in range(12):
        add(90+i,"192.0.2.90",domain=hashlib.sha256(str(i).encode()).hexdigest()[:52]+".telemetry.example")
    for i in range(48):
        add(i*3,"192.0.2.10",dst="198.51.100.10",protocol="TLS",port=443,domain="",length=1200)
    return sorted(rows,key=lambda r:r["timestamp"])

def best_window(rows, distinct_ports=False, width=60):
    rows=sorted(rows,key=lambda r:r["timestamp"])
    left=0; best=(0,0); best_score=-1
    counts=collections.Counter()
    for right,row in enumerate(rows):
        counts[row["port"]]+=1
        while row["timestamp"]-rows[left]["timestamp"]>width:
            port=rows[left]["port"]; counts[port]-=1
            if not counts[port]: del counts[port]
            left+=1
        score=len(counts) if distinct_ports else right-left+1
        if score>best_score:
            best_score=score; best=(left,right+1)
    return rows[best[0]:best[1]]

RULES={
    "TCP-SCAN":dict(name="TCP port sweep",severity="High",threshold="12 distinct destination ports on one target within 60 seconds",
       explanation="Many SYN connection attempts across different ports can indicate service discovery. An authorized scanner can look the same.",
       next_steps=["Confirm whether the source is an authorized scanner.","Inspect SYN/ACK and reset responses in Wireshark.","Compare the target ports with the approved service inventory."]),
    "DNS-BURST":dict(name="DNS query burst",severity="Medium",threshold="40 DNS queries from one client within 60 seconds",
       explanation="A concentrated burst may come from retries, automation or unusual application behavior; it is not proof of an attack.",
       next_steps=["Identify the process and expected workload on the client.","Review query timing and resolver errors.","Compare with a longer baseline before changing network policy."]),
    "DNS-NXDOMAIN":dict(name="High NXDOMAIN response ratio",severity="Medium",threshold="At least 20 DNS responses with 65% or more NXDOMAIN",
       explanation="Frequent failed lookups can reflect a broken application, stale configuration or generated names. Responses are grouped by destination client.",
       next_steps=["Inspect the queried names and associated application.","Check DNS configuration and spelling.","Compare with resolver logs before escalating."]),
    "DNS-LONG":dict(name="Repeated long DNS labels",severity="Medium",threshold="At least 8 queried names with a label of 45 or more characters",
       explanation="Long labels are a review signal, not a tunneling verdict. Tracking, security products and legitimate services also use them.",
       next_steps=["Check the application that generated the names.","Review label patterns and traffic volume.","Validate with a known-good baseline; do not block solely on label length."])
}
def analyze(rows, source="Synthetic training scenario", synthetic=False):
    rows=sorted(rows,key=lambda r:r["timestamp"])
    alerts=[]
    def emit(rule,subject,evidence,observed):
        spec=RULES[rule]
        alerts.append(dict(id=f"AL-{len(alerts)+1:03}",rule=rule,subject=subject,evidence=evidence[:12],evidence_total=len(evidence),
                           observed=observed,status="New",**spec))
    scans=collections.defaultdict(list); queries=collections.defaultdict(list); replies=collections.defaultdict(list)
    for r in rows:
        if r["syn"] and r["port"]:
            scans[(r["src"],r["dst"])].append(r)
        if r["domain"] and not r["response"]:
            queries[r["src"]].append(r)
        if r["response"] and r["domain"]:
            replies[r["dst"]].append(r)
    for (src,dst), events in scans.items():
        best=best_window(events,distinct_ports=True)
        count=len({x["port"] for x in best})
        if count>=12:
            emit("TCP-SCAN",src,[dict(frame=x["frame"],time=x["timestamp"],detail=f'{dst}:{x["port"]} SYN') for x in best],f"{count} distinct ports in 60 seconds")
    for src,events in queries.items():
        best=best_window(events)
        if len(best)>=40:
            emit("DNS-BURST",src,[dict(frame=x["frame"],time=x["timestamp"],detail=x["domain"]) for x in best],f"{len(best)} queries in 60 seconds")
        long=[r for r in events if max(map(len,r["domain"].split(".")))>=45]
        if len(long)>=8:
            emit("DNS-LONG",src,[dict(frame=x["frame"],time=x["timestamp"],detail=x["domain"]) for x in long],f"{len(long)} queries with long labels")
    for client,events in replies.items():
        failed=[r for r in events if r["rcode"]==3]
        if len(events)>=20 and len(failed)/len(events)>=.65:
            emit("DNS-NXDOMAIN",client,[dict(frame=x["frame"],time=x["timestamp"],detail=x["domain"]) for x in failed],f"{len(failed)}/{len(events)} responses are NXDOMAIN")
    rank={"High":0,"Medium":1,"Low":2}
    alerts.sort(key=lambda a:rank[a["severity"]])
    protocols=collections.Counter(r["protocol"] for r in rows)
    domains=collections.Counter(r["domain"] for r in rows if r["domain"] and not r["response"])
    clients=collections.Counter(r["src"] for r in rows)
    start=rows[0]["timestamp"]; end=rows[-1]["timestamp"]; duration=end-start
    bins=[0]*24
    for r in rows:
        bins[min(23,int((r["timestamp"]-start)/max(duration,1)*23))]+=1
    dns_queries=sum(len(v) for v in queries.values())
    blocked=sum(1 for r in rows if r["blocked"] and not r["response"])
    digest=hashlib.sha256(source.encode())
    for row in rows: digest.update(json.dumps(row,sort_keys=True).encode())
    return dict(id="CASE-"+digest.hexdigest()[:8].upper(),
        source=source,synthetic=synthetic,created=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        metrics=dict(events=len(rows),bytes=int(sum(r["length"] for r in rows)),duration=round(duration,2),
                     hosts=len({r["src"] for r in rows}|{r["dst"] for r in rows}),dns_queries=dns_queries,blocked=blocked,
                     high=sum(a["severity"]=="High" for a in alerts),alerts=len(alerts)),
        protocols=[dict(name=k,count=v) for k,v in protocols.most_common()],
        unique_domains=len(domains),domains=[dict(name=k,count=v) for k,v in domains.most_common(12)],
        clients=[dict(name=k,count=v) for k,v in clients.most_common(8)],
        timeline=bins,alerts=alerts,rule_count=len(RULES),
        limitations=["Heuristic review signals; false positives are expected.","Passive file analysis only; no live capture or scanning.",
          "Encrypted payloads are not decrypted. DNS visibility depends on the capture.",
          "PCAP is limited to the first 100,000 packets; CSV/log input rejects more than 100,000 events.",
          "Pi-hole native logs use the current local year; adjacent block lines are best-effort matches.",
          "Blocked counts reflect log/CSV flags, not independently verified protection."])

def external_summary(case):
    # Deliberately exclude addresses, domains, filenames and packet evidence.
    return dict(case_id=case["id"],synthetic=case["synthetic"],metrics=case["metrics"],
                findings=[dict(rule=a["rule"],severity=a["severity"],observed=a["observed"]) for a in case["alerts"]],
                caveat="Heuristics, not confirmed incidents. Do not invent evidence or recommend automatic blocking.")

def csv_bytes(rows):
    out=io.StringIO()
    keys=["timestamp","src","dst","protocol","length","port","syn","domain","response","rcode","blocked"]
    w=csv.DictWriter(out,fieldnames=keys,extrasaction="ignore"); w.writeheader(); w.writerows(rows)
    return out.getvalue().encode()

