import socket
import time

TARGET = "185.220.101.45"

print(f"Hammering {TARGET} to trigger auto-block...")
for i in range(15):
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect(("127.0.0.1", 2222))
        s.recv(64)
        s.send(f"SSH-2.0-OpenSSH_7.4\r\nroot password123 src={TARGET}".encode())
        s.close()
    except Exception as e:
        print(f"  error: {e}")
    print(f"  [{i+1}/15] hit sent")
    time.sleep(0.3)

print("\nDone — check uvicorn logs for AUTO-BLOCKED")