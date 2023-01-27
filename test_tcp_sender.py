import socket
import random
import string
import time

DEST_IP = "127.0.0.1"
DEST_PORT = 1111
# TODO fails when is bigger than 16339
MSG_LEN = 16339
TIME_BETWEEN_MSG = 2 # seconds

def send_msg(sock, msg):
    total_sent = 0
    while total_sent < len(msg):
        sent = sock.send(msg[total_sent:])
        if sent == 0:
            raise RuntimeError("socket connection broken")
        print("sent: %d, %s" % (sent, msg[total_sent:total_sent + sent]))
        total_sent = total_sent + sent

print("TCP target IP: %s" % DEST_IP)
print("TCP target port: %s" % DEST_PORT)

# create an INET, STREAMing socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# now connect to the web server on port 80 - the normal http port
s.connect((DEST_IP, DEST_PORT))

while True:
    message = ''.join(random.choices(string.ascii_lowercase, k=MSG_LEN))
    send_msg(s, message.encode('utf-8'))
    time.sleep(TIME_BETWEEN_MSG)
