from datetime import datetime, timezone
from typing import Optional
start_time = datetime.now(timezone.utc)
certstream_connected = False
last_cert_time: Optional[datetime] = None
total_certs_observed = 0

def set_certstream_status(connected: bool):
    global certstream_connected
    certstream_connected = connected

def record_cert_received():
    global last_cert_time, total_certs_observed
    last_cert_time = datetime.now(timezone.utc)
    total_certs_observed += 1
