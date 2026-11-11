"""
Generate live honeypot traffic with spoofed attacker IPs for GeoIP / threat map.
"""
import socket
import time
import random

FAKE_IPS = [
    "185.220.101.45",
    "194.165.16.72",
    "45.142.212.100",
    "103.21.244.0",
    "191.96.249.55",
    "80.82.77.139",
    "162.247.74.201",
    "176.10.104.240",
    "51.15.43.205",
    "109.201.133.195",
    "221.194.47.242",
    "41.206.188.185",
    "203.0.113.42",
    "198.51.100.77",
    "192.0.2.123",
]


def hit_ssh(ip):
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect(("127.0.0.1", 2222))
        s.recv(64)
        payloads = [
            f"SSH-2.0-OpenSSH_7.4\r\nroot password123 src={ip}\r\n".encode(),
            f"SSH-2.0-PuTTY\r\nadmin admin src={ip}\r\n".encode(),
            b"\x00" * 40 + f"root src={ip}\r\n".encode(),
        ]
        s.send(random.choice(payloads))
        s.close()
    except Exception as e:
        print(f"SSH: {e}")


def hit_http(ip):
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect(("127.0.0.1", 8080))
        payloads = [
            f"GET /admin HTTP/1.1\r\nHost: target\r\nX-Forwarded-For: {ip}\r\n\r\n".encode(),
            f"GET /?id=1' UNION SELECT * FROM users-- HTTP/1.1\r\nHost: target\r\nX-Forwarded-For: {ip}\r\n\r\n".encode(),
            f"GET /wp-login.php HTTP/1.1\r\nHost: target\r\nX-Forwarded-For: {ip}\r\n\r\n".encode(),
            f"GET /.env HTTP/1.1\r\nHost: target\r\nX-Forwarded-For: {ip}\r\n\r\n".encode(),
            f"GET /../../etc/passwd HTTP/1.1\r\nHost: target\r\nX-Forwarded-For: {ip}\r\n\r\n".encode(),
            f"POST /login HTTP/1.1\r\nHost: target\r\nX-Forwarded-For: {ip}\r\n\r\nusername=admin&password=' OR '1'='1".encode(),
        ]
        s.send(random.choice(payloads))
        try:
            s.recv(256)
        except Exception:
            pass
        s.close()
    except Exception as e:
        print(f"HTTP: {e}")


def hit_ftp(ip):
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect(("127.0.0.1", 2121))
        s.recv(64)
        s.send(f"USER anonymous src={ip}\r\n".encode())
        s.close()
    except Exception as e:
        print(f"FTP: {e}")


def hit_telnet(ip):
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect(("127.0.0.1", 2323))
        s.recv(64)
        s.send(f"root\r\npassword123\r\nsrc={ip}\r\n".encode())
        s.close()
    except Exception as e:
        print(f"Telnet: {e}")


print("=== Phase 1: geo-tagged mixed traffic ===")
for i in range(40):
    ip = random.choice(FAKE_IPS)
    fn = random.choice([hit_ssh, hit_http, hit_ftp, hit_telnet])
    fn(ip)
    print(f"  [{i+1}/40] {fn.__name__} ← {ip}")
    time.sleep(0.3)

print("\n=== Phase 2: multi-port campaign (same IP) ===")
camp_ip = "194.165.16.72"
for i in range(3):
    hit_ssh(camp_ip)
    hit_http(camp_ip)
    hit_ftp(camp_ip)
    print(f"  [{i+1}/3] multi-port ← {camp_ip}")
    time.sleep(0.4)

print("\n=== Phase 3: repeat-offender auto-contain ===")
target = "185.220.101.45"
for i in range(12):
    hit_ssh(target)
    print(f"  [{i+1}/12] SSH hammer ← {target}")
    time.sleep(0.2)

print("\nDone. Watch Overview threat map + Alert Queue light up LIVE.")
