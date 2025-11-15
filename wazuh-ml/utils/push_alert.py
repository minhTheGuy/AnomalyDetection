# push_alert.py
import requests
from core.config import (
    WAZUH_MANAGER_API,
    WAZUH_MANAGER_USER,
    WAZUH_MANAGER_PASS,
    get_requests_verify,
)

def send_alert(message: str):
    url = f"{WAZUH_MANAGER_API}/manager/logs"
    payload = { "log": message }
    resp = requests.post(
        url,
        auth=(WAZUH_MANAGER_USER, WAZUH_MANAGER_PASS),
        json=payload,
        verify=get_requests_verify()
    )
    print("Sent:", resp.status_code, resp.text)

if __name__ == "__main__":
    send_alert("ML anomaly: possible suspicious activity from 172.16.158.1 to dst port 22")
