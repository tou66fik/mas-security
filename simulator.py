import asyncio, aio_pika, json, random
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
