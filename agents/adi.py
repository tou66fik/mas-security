from base_agent import BaseAgent
from config import QUEUES

class AgentADI(BaseAgent):
    def __init__(self): super().__init__("AgentADI")
    async def setup(self): await self.subscribe(QUEUES["raw_brute"], self.detect)
    async def detect(self, raw: dict):
        if raw.get("failed_attempts", 0) >= 5:
            await self.publish(QUEUES["detection"], {"threat_type":"BRUTE_FORCE","source_ip":raw["ip"],"confidence":min(1.0,raw["failed_attempts"]/10),"geo":raw.get("geo","FR")})
