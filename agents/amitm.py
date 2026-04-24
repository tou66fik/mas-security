from base_agent import BaseAgent
from config import QUEUES

class AgentAMITM(BaseAgent):
    def __init__(self): super().__init__("AgentAMITM")
    async def setup(self): await self.subscribe(QUEUES["raw_mitm"], self.detect)
    async def detect(self, raw: dict):
        if raw.get("cert_fingerprint")=="mismatch" or raw.get("arp_anomaly"):
            await self.publish(QUEUES["detection"], {"threat_type":"MITM","source_ip":raw["ip"],"confidence":0.90,"geo":raw.get("geo","DE")})
