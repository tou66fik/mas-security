from base_agent import BaseAgent
from config import QUEUES

class AgentASI(BaseAgent):
    def __init__(self): super().__init__("AgentASI")
    async def setup(self): await self.subscribe(QUEUES["raw_sqli"], self.detect)
    async def detect(self, raw: dict):
        if any(k in raw.get("payload","").upper() for k in ["UNION","SELECT","--","OR 1=1"]):
            await self.publish(QUEUES["detection"], {"threat_type":"SQL_INJECTION","source_ip":raw["ip"],"confidence":0.95,"geo":raw.get("geo","US")})
