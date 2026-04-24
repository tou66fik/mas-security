import asyncio, aiohttp
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
        msg = f"🚨 *THREAT* | {alert['threat_type']} | {alert['source_ip']} | Score:{score}\nRépondre: `approve {aid}` ou `deny {aid}`"
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
