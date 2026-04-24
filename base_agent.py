import asyncio, aio_pika, json, logging
from typing import Callable
from config import RABBITMQ_URL, EXCHANGE

logging.basicConfig(level=logging.INFO, format="%(levelname)s [%(name)s] %(message)s")

class BaseAgent:
    def __init__(self, name: str):
        self.name = name
        self.connection = self.channel = self.exchange = None

    async def connect(self):
        max_retries = 10
        for attempt in range(max_retries):
            try:
                self.connection = await aio_pika.connect_robust(RABBITMQ_URL, timeout=10)
                self.channel = await self.connection.channel()
                self.exchange = await self.channel.declare_exchange(EXCHANGE, aio_pika.ExchangeType.TOPIC)
                logging.info(f"🟢 {self.name} connecté au broker")
                return
            except Exception as e:
                wait = min(2 ** attempt, 30)
                logging.warning(f"⚠️ {self.name} échec connexion ({attempt+1}/{max_retries}): {e}. Reprise dans {wait}s...")
                await asyncio.sleep(wait)
        raise RuntimeError(f"❌ {self.name} impossible de se connecter après {max_retries} tentatives")

    async def subscribe(self, queue_name: str, callback: Callable):
        q = await self.channel.declare_queue(queue_name, durable=True)
        await q.bind(self.exchange, routing_key=queue_name)
        # _wrap retourne une fonction, pas une coroutine → compatible aio-pika
        await q.consume(self._wrap(callback))
        logging.info(f"👂 {self.name} écoute: {queue_name}")

    async def publish(self, routing_key: str, payload: dict):
        await self.exchange.publish(
            aio_pika.Message(
                body=json.dumps(payload).encode(),
                delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
                headers={"source_agent": self.name}
            ),
            routing_key=routing_key
        )

    def _wrap(self, cb: Callable):  # ← PAS async ici !
        async def inner(msg: aio_pika.IncomingMessage):
            async with msg.process():
                try:
                    data = json.loads(msg.body.decode())
                    await cb(data)
                except json.JSONDecodeError as e:
                    logging.error(f"❌ {self.name} JSON error: {e}")
                except Exception as e:
                    logging.error(f"❌ {self.name} callback error: {e}", exc_info=True)
        return inner

    async def run(self, setup_fn: Callable):
        await self.connect()
        await setup_fn()
        while True:
            await asyncio.sleep(1)
