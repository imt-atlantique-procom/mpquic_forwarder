import socket

DEST_IP = "127.0.0.1"
DEST_PORT = 1111

def send_msg(sock, msg):
    total_sent = 0
    while total_sent < len(msg):
        sent = sock.send(msg[total_sent:])
        if sent == 0:
            raise RuntimeError("socket connection broken")
        total_sent = total_sent + sent
        print("sent: %d" % sent)

print("TCP target IP: %s" % DEST_IP)
print("TCP target port: %s" % DEST_PORT)

# create an INET, STREAMing socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
message = b"Hello, World!"

# now connect to the web server on port 80 - the normal http port
s.connect((DEST_IP, DEST_PORT))
send_msg(s, message)
