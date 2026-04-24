import asyncio, json, logging, yaml
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
        with open(LOG_FILE, "a") as f: f.write(f"[AA] {v['threat_type']} | Score:{v['risk_score']}\n")
        await self.publish(QUEUES["verified"], v)

class AgentAR(BaseAgent):
    def __init__(self): super().__init__("AR_PROD")
    async def setup(self): await self.subscribe(QUEUES["approved"], self.respond)
    async def respond(self, app: dict):
        if app.get("status") not in ["AUTO_APPROVED", "APPROVED"]: return
        txt = f"[AR] ✅ BLOQUÉ {app['source_ip']} | {app['threat_type']} | MITRE:{app.get('mitre',{}).get('technique_id')} | Score:{app['risk_score']}"
        print(txt)
        with open(LOG_FILE, "a") as f: f.write(txt+"\n")
        await self.publish(QUEUES["actions"], {"type":"EXECUTED","ip":app['source_ip']})
