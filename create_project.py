#!/usr/bin/env python3
"""
Génère automatiquement l'arborescence complète du projet MAS Security.
"""
import os
from pathlib import Path

def write(path: str, content: str):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    print(f"✅ Créé: {path}")

def make_exec(path: str):
    os.chmod(path, 0o755)

# 📁 STRUCTURE & FICHIERS
write("requirements.txt", """aio-pika==9.4.0
streamlit==1.31.0
pandas==2.1.0
fpdf2==2.7.6
matplotlib==3.8.0
elasticsearch[async]==8.11.0
pyyaml==6.0.1
aiohttp==3.9.0
""")

write("config.py", """RABBITMQ_URL = "amqp://mas_user:mas_pass@localhost:5672/"
EXCHANGE = "mas_security"
QUEUES = {
    "raw_brute": "raw.brute_force",
    "raw_sqli": "raw.sqli",
    "raw_csrf": "raw.csrf",
    "raw_mitm": "raw.mitm",
    "raw_trojan": "raw.trojan",
    "detection": "alerts.detection",
    "verified": "alerts.verified",
    "approved": "alerts.approved",
    "actions": "alerts.actions",
    "approval_resp": "approval.response"
}
LOG_FILE = "monitor.log"
""")

write("base_agent.py", """import asyncio, aio_pika, json, logging
from typing import Callable
from config import RABBITMQ_URL, EXCHANGE

logging.basicConfig(level=logging.INFO, format="%(levelname)s [%(name)s] %(message)s")

class BaseAgent:
    def __init__(self, name: str):
        self.name = name
        self.connection = self.channel = self.exchange = None

    async def connect(self):
        self.connection = await aio_pika.connect_robust(RABBITMQ_URL)
        self.channel = await self.connection.channel()
        self.exchange = await self.channel.declare_exchange(EXCHANGE, aio_pika.ExchangeType.TOPIC)
        logging.info(f"🟢 {self.name} connecté au broker")

    async def subscribe(self, queue_name: str, callback: Callable):
        q = await self.channel.declare_queue(queue_name, durable=True)
        await q.bind(self.exchange, routing_key=queue_name)
        await q.consume(self._wrap(callback))
        logging.info(f"👂 {self.name} écoute: {queue_name}")

    async def publish(self, routing_key: str, payload: dict):
        await self.exchange.publish(
            aio_pika.Message(body=json.dumps(payload).encode(), delivery_mode=aio_pika.DeliveryMode.PERSISTENT),
            routing_key=routing_key
        )

    async def _wrap(self, cb: Callable):
        async def inner(msg: aio_pika.IncomingMessage):
            async with msg.process():
                await cb(json.loads(msg.body.decode()))
        return inner

    async def run(self, setup_fn: Callable):
        await self.connect()
        await setup_fn()
        while True: await asyncio.sleep(1)
""")

write("mitre_enricher.py", """import yaml
from pathlib import Path

class MITREEnricher:
    def __init__(self, path="config/prod/mitre_mapping.yaml"):
        with open(path) as f: self.mapping = yaml.safe_load(f)
    def enrich(self, alert: dict) -> dict:
        t = alert.get("threat_type", "").upper()
        m = self.mapping.get(t, {})
        return {**alert, "mitre": m, "stix_type": "indicator", "labels": [f"attack-pattern/{m.get('technique_id','?')}"]}
""")

write("config/prod/mitre_mapping.yaml", """BRUTE_FORCE:
  technique_id: "T1110"
  tactic: "Credential Access"
SQL_INJECTION:
  technique_id: "T1190"
  tactic: "Initial Access"
CSRF:
  technique_id: "T1189"
  tactic: "Initial Access"
MITM:
  technique_id: "T1557"
  tactic: "Credential Access"
TROJAN_C2:
  technique_id: "T1071.001"
  tactic: "Command and Control"
""")

write("config/prod/definitions.json", """{
  "users": [{"name": "mas_user", "password": "mas_pass", "tags": "monitoring"}],
  "vhosts": [{"name": "mas_vhost"}],
  "permissions": [{"user": "mas_user", "vhost": "mas_vhost", "configure": ".*", "write": ".*", "read": ".*"}]
}
""")

write("config/prod/rabbitmq.conf", """listeners.ssl.default = 5671
ssl_options.cacertfile = /etc/rabbitmq/certs/ca.pem
ssl_options.certfile   = /etc/rabbitmq/certs/server.pem
ssl_options.keyfile    = /etc/rabbitmq/certs/server.key
ssl_options.verify     = verify_peer
ssl_options.fail_if_no_peer_cert = true
default_user = mas_admin
default_pass = MasPr0d2026!
management.load_definitions = /etc/rabbitmq/definitions.json
""")

write("scripts/generate_certs.sh", """#!/bin/bash
mkdir -p certs && cd certs
openssl genrsa -out ca.key 2048 && openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.pem -subj "/CN=MAS-CA"
openssl genrsa -out server.key 2048 && openssl req -new -key server.key -out server.csr -subj "/CN=rabbitmq" && openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 365
openssl genrsa -out client.key 2048 && openssl req -new -key client.key -out client.csr -subj "/CN=mas-agents" && openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.pem -days 365
echo "✅ Certificats générés dans certs/"
""")
make_exec("scripts/generate_certs.sh")

# 🤖 AGENTS
write("agents/__init__.py", "")

def agent(name, queue, condition, payload):
    return f"""from base_agent import BaseAgent
from config import QUEUES

class Agent{name}(BaseAgent):
    def __init__(self): super().__init__("Agent{name}")
    async def setup(self): await self.subscribe(QUEUES["{queue}"], self.detect)
    async def detect(self, raw: dict):
        if {condition}:
            await self.publish(QUEUES["detection"], {payload})
"""

write("agents/adi.py", agent("ADI", "raw_brute", 'raw.get("failed_attempts", 0) >= 5', '{"threat_type":"BRUTE_FORCE","source_ip":raw["ip"],"confidence":min(1.0,raw["failed_attempts"]/10),"geo":raw.get("geo","FR")}'))
write("agents/asi.py", agent("ASI", "raw_sqli", 'any(k in raw.get("payload","").upper() for k in ["UNION","SELECT","--","OR 1=1"])', '{"threat_type":"SQL_INJECTION","source_ip":raw["ip"],"confidence":0.95,"geo":raw.get("geo","US")}'))
write("agents/acsrf.py", agent("ACSRF", "raw_csrf", 'raw.get("missing_token", False)', '{"threat_type":"CSRF","source_ip":raw["ip"],"confidence":0.85,"geo":raw.get("geo","CN")}'))
write("agents/amitm.py", agent("AMITM", "raw_mitm", 'raw.get("cert_fingerprint")=="mismatch" or raw.get("arp_anomaly")', '{"threat_type":"MITM","source_ip":raw["ip"],"confidence":0.90,"geo":raw.get("geo","DE")}'))
write("agents/act.py", agent("ACT", "raw_trojan", 'raw.get("c2_beacon", False)', '{"threat_type":"TROJAN_C2","source_ip":raw["ip"],"confidence":0.98,"geo":raw.get("geo","IR")}'))

write("agents/aapprove.py", """import asyncio, aiohttp
from base_agent import BaseAgent
from config import QUEUES

class AgentAPROVE(BaseAgent):
    def __init__(self, slack_webhook: str = "", timeout: int = 30):
        super().__init__("APROVE")
        self.webhook, self.timeout, self.pending = slack_webhook, timeout, {}

    async def setup(self):
        await self.subscribe(QUEUES["verified"], self.request)
        await self.subscribe(QUEUES["approval_resp"], self.reply)

    async def request(self, alert: dict):
        score = alert.get("risk_score", 0)
        if score < 0.85:
            await self.publish(QUEUES["approved"], {**alert, "status": "AUTO_APPROVED"})
            return
        aid = alert.get("event_id", "unknown")
        msg = f"🚨 *THREAT* | {alert['threat_type']} | {alert['source_ip']} | Score:{score}\\nRépondre: `approve {aid}` ou `deny {aid}`"
        if self.webhook:
            async with aiohttp.ClientSession() as s:
                await s.post(self.webhook, json={"text": msg})
        evt = asyncio.Event()
        self.pending[aid] = evt
        try:
            await asyncio.wait_for(evt.wait(), self.timeout)
            res = "APPROVED"
        except asyncio.TimeoutError: res = "DENIED_TIMEOUT"
        await self.publish(QUEUES["approved"], {**alert, "status": res, "approved_by": "human"})

    async def reply(self, resp: dict):
        if resp.get("alert_id") in self.pending:
            self.pending[resp["alert_id"]].set()
""")

write("orchestrator_prod.py", """import asyncio, json, logging, yaml
from base_agent import BaseAgent
from config import QUEUES, LOG_FILE
from mitre_enricher import MITREEnricher

logging.basicConfig(level=logging.INFO, format="%(message)s")

class AgentAA(BaseAgent):
    def __init__(self, enricher: MITREEnricher):
        super().__init__("AA_PROD")
        self.enricher = enricher
    async def setup(self): await self.subscribe(QUEUES["detection"], self.enrich)
    async def enrich(self, raw: dict):
        e = self.enricher.enrich(raw)
        score = min(1.0, e["confidence"] + (0.15 if e.get("geo") not in ["FR","EU"] else 0.0))
        v = {**e, "risk_score": round(score, 2), "status": "PENDING" if score >= 0.85 else "BLOCK"}
        with open(LOG_FILE, "a") as f: f.write(f"[AA] {v['threat_type']} | Score:{v['risk_score']}\\n")
        await self.publish(QUEUES["verified"], v)

class AgentAR(BaseAgent):
    def __init__(self): super().__init__("AR_PROD")
    async def setup(self): await self.subscribe(QUEUES["approved"], self.respond)
    async def respond(self, app: dict):
        if app.get("status") not in ["AUTO_APPROVED", "APPROVED"]: return
        txt = f"[AR] ✅ BLOQUÉ {app['source_ip']} | {app['threat_type']} | MITRE:{app.get('mitre',{}).get('technique_id')} | Score:{app['risk_score']}"
        print(txt)
        with open(LOG_FILE, "a") as f: f.write(txt+"\\n")
        await self.publish(QUEUES["actions"], {"type":"EXECUTED","ip":app['source_ip']})
""")

write("simulator.py", """import asyncio, aio_pika, json, random
from config import RABBITMQ_URL, EXCHANGE, QUEUES

ATTACKS = {
    QUEUES["raw_brute"]: {"ip":"10.0.1.55","failed_attempts":8,"geo":"RU"},
    QUEUES["raw_sqli"]:  {"ip":"192.168.2.10","payload":"1' UNION SELECT * FROM users--","geo":"US"},
    QUEUES["raw_csrf"]:  {"ip":"172.16.0.44","missing_token":True,"geo":"CN"},
    QUEUES["raw_mitm"]:  {"ip":"10.0.5.12","cert_fingerprint":"mismatch","arp_anomaly":True,"geo":"DE"},
    QUEUES["raw_trojan"]:{ "ip":"10.0.3.88","c2_beacon":True,"process":"svchost_x.exe","geo":"IR"}
}

async def simulate():
    conn = await aio_pika.connect_robust(RABBITMQ_URL)
    ch = await conn.channel()
    ex = await ch.declare_exchange(EXCHANGE, aio_pika.ExchangeType.TOPIC)
    while True:
        for q, p in ATTACKS.items():
            p["event_id"] = f"evt_{random.randint(1000,9999)}"
            await ex.publish(aio_pika.Message(body=json.dumps(p).encode()), routing_key=q)
            print(f"[SIM] ➡️ {q}")
        await asyncio.sleep(4)

if __name__=="__main__": asyncio.run(simulate())
""")

write("dashboard.py", """import streamlit as st, pandas as pd, time, os
from config import LOG_FILE
st.set_page_config(page_title="MAS Dashboard", layout="wide")
st.title("🛡️ MAS Security Dashboard")
col1, col2 = st.columns(2)
with col1:
    st.subheader("📡 Actions AR")
    logs = [l.strip() for l in open(LOG_FILE).readlines() if l.strip()] if os.path.exists(LOG_FILE) else []
    st.dataframe(pd.DataFrame({"Événement": logs}), height=400)
with col2:
    st.subheader("📊 Métriques")
    blocked = [l for l in logs if "BLOQUÉ" in l]
    st.metric("Alertes", len(logs))
    st.metric("IPs bloquées", len(blocked))
    st.metric("Dernière", blocked[-1].split("|")[1].strip() if blocked else "Aucune")
time.sleep(2); st.rerun()
""")

write("kibana_exporter.py", """#!/usr/bin/env python3
import argparse, logging, os, tempfile, pandas as pd, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from elasticsearch import Elasticsearch
from fpdf import FPDF
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fetch(es_url, index, days):
    es = Elasticsearch(es_url)
    start = (datetime.now()-timedelta(days=days)).isoformat()
    res = es.search(index=index, query={"range":{"@timestamp":{"gte":start}}}, size=10000, sort=[{"@timestamp":"desc"}])
    return [h["_source"] for h in res["hits"]["hits"]]

def flatten(data):
    out=[]
    for d in data:
        e=d.get("extra",{})
        out.append({"timestamp":d.get("@timestamp"),"threat":e.get("threat_type","N/A"),"ip":e.get("source_ip","?"),
                     "mitre":e.get("mitre",{}).get("technique_id","?"),"score":e.get("risk_score",0),"status":e.get("status","?")})
    df=pd.DataFrame(out); df["timestamp"]=pd.to_datetime(df["timestamp"],errors="coerce")
    return df.dropna(subset=["threat"])

def export_pdf(df, outdir, days):
    p=os.path.join(outdir, f"mas_{datetime.now():%Y%m%d_%H%M}.pdf")
    class Rep(FPDF):
        def header(self): self.set_font("Helvetica","B",12); self.cell(0,10,"MAS Security Report",align="C",new_x="LMARGIN",new_y="NEXT"); self.ln(4)
        def footer(self): self.set_y(-15); self.set_font("Helvetica","I",8); self.cell(0,10,f"Page {self.page_no()}/{{nb}}",align="C")
    pdf=Rep(); pdf.add_page()
    pdf.set_font("Helvetica","B",10); pdf.cell(0,8,f"Période: {days}j | Alertes: {len(df)}",new_x="LMARGIN",new_y="NEXT"); pdf.ln(5)
    tmp=tempfile.mkdtemp()
    plt.figure(); df["mitre"].value_counts().head(5).plot(kind="bar",color="#2E7D32"); plt.tight_layout()
    i1=f"{tmp}/m.png"; plt.savefig(i1,dpi=120); plt.close(); pdf.image(i1,w=180); pdf.ln(5)
    pdf.set_font("Helvetica","",9)
    for _,r in df.head(20).iterrows(): pdf.cell(0,5,f"{r['timestamp']} | {r['threat']} | {r['ip']} | {r['mitre']} | S:{r['score']}",new_x="LMARGIN",new_y="NEXT")
    pdf.output(p); logger.info(f"📕 PDF: {p}")
    return p

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--es",default="http://localhost:9200"); ap.add_argument("--index",default="mas-alerts")
    ap.add_argument("--days",type=int,default=7); ap.add_argument("--out",default="./reports"); ap.add_argument("--fmt",choices=["csv","pdf","both"],default="both")
    a=ap.parse_args(); os.makedirs(a.out,exist_ok=True)
    data=fetch(a.es, a.index, a.days)
    if not data: logger.warning("Aucune donnée."); return
    df=flatten(data)
    if a.fmt in ["csv","both"]: pd.DataFrame(df).to_csv(f"{a.out}/mas.csv",index=False); logger.info("📄 CSV généré")
    if a.fmt in ["pdf","both"]: export_pdf(df, a.out, a.days)

if __name__=="__main__": main()
""")

write("docker-compose.yml", """version: '3.8'
services:
  rabbitmq:
    image: rabbitmq:3-management
    container_name: mas_rabbitmq
    ports: ["5672:5672","15672:15672"]
    environment:
      RABBITMQ_DEFAULT_USER: mas_user
      RABBITMQ_DEFAULT_PASS: mas_pass
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    container_name: mas_es
    ports: ["9200:9200"]
    environment:
      discovery.type: single-node
      xpack.security.enabled: "false"
""")

write("main.py", """import asyncio
from agents.adi import AgentADI
from agents.asi import AgentASI
from agents.acsrf import AgentACSRF
from agents.amitm import AgentAMITM
from agents.act import AgentACT
from agents.aapprove import AgentAPROVE
from orchestrator_prod import AgentAA, AgentAR
from mitre_enricher import MITREEnricher

async def main():
    enricher = MITREEnricher()
    agents = [AgentADI(), AgentASI(), AgentACSRF(), AgentAMITM(), AgentACT(),
              AgentAA(enricher), AgentAR(), AgentAPROVE(slack_webhook="", timeout=25)]
    await asyncio.gather(*(a.run(a.setup) for a in agents))

if __name__=="__main__": asyncio.run(main())
""")

print("\n🚀 Projet MAS Security généré avec succès !")
print("📖 Consultez README.md ou lancez: pip install -r requirements.txt && docker compose up -d && python main.py")

