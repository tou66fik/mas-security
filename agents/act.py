from base_agent import BaseAgent
from config import QUEUES

class AgentACT(BaseAgent):
    def __init__(self): super().__init__("AgentACT")
    async def setup(self): await self.subscribe(QUEUES["raw_trojan"], self.detect)
    async def detect(self, raw: dict):
        if raw.get("c2_beacon", False):
            await self.publish(QUEUES["detection"], {"threat_type":"TROJAN_C2","source_ip":raw["ip"],"confidence":0.98,"geo":raw.get("geo","IR")})
