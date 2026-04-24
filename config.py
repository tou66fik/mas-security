# config.py
import os

RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "localhost")
# Le vhost '/' doit être encodé en '%2F' dans l'URL AMQP
RABBITMQ_URL = f"amqp://mas_user:mas_pass@{RABBITMQ_HOST}:5672/%2F"

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
