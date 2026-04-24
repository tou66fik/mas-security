from base_agent import BaseAgent
from config import QUEUES

class AgentACSRF(BaseAgent):
    def __init__(self): super().__init__("AgentACSRF")
    async def setup(self): await self.subscribe(QUEUES["raw_csrf"], self.detect)
    async def detect(self, raw: dict):
        if raw.get("missing_token", False):
            await self.publish(QUEUES["detection"], {"threat_type":"CSRF","source_ip":raw["ip"],"confidence":0.85,"geo":raw.get("geo","CN")})
