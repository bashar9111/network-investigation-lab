"""Launch the local app and reopen it reliably, without a persistent console."""
import http.client, json, os, pathlib, subprocess, sys, time, webbrowser
ROOT=pathlib.Path(__file__).resolve().parent
def ready(port):
    conn=http.client.HTTPConnection("127.0.0.1",port,timeout=.5)
    try:
        conn.request("GET","/api/status")
        return json.load(conn.getresponse()).get("application")=="network-investigation-lab"
    except Exception:return False
    finally:conn.close()
def main():
    for port in range(8766,8776):
        if ready(port):
            webbrowser.open(f"http://127.0.0.1:{port}")
            print(f"Opened http://127.0.0.1:{port}");return
    runtime=ROOT/"runtime";runtime.mkdir(exist_ok=True)
    for port in range(8766,8776):
        with (runtime/"server.log").open("ab") as log:
            process=subprocess.Popen([sys.executable,str(ROOT/"app.py"),"--port",str(port)],cwd=ROOT,
                stdout=log,stderr=log,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
        for _ in range(20):
            if ready(port):
                (runtime/"server.json").write_text(json.dumps({"pid":process.pid,"port":port}),encoding="utf-8")
                webbrowser.open(f"http://127.0.0.1:{port}")
                print(f"Opened http://127.0.0.1:{port}");return
            if process.poll() is not None:break
            time.sleep(.2)
        if process.poll() is None:process.terminate()
    raise SystemExit("Could not start the local lab. Check runtime/server.log or run: python app.py --port 8776")
if __name__=="__main__":main()

