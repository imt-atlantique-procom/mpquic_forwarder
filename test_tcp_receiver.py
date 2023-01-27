import socket

BIND_IP = "127.0.0.1"
BIND_PORT = 3333
BUFFER_SIZE = 65536

serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.bind((BIND_IP, BIND_PORT))
# become a server socket
serversocket.listen(5)

print("Listening on %s:%s" % (BIND_IP, BIND_PORT))

(clientsocket, address) = serversocket.accept()
print("Connected from ", address)

while True:
    data = clientsocket.recv(BUFFER_SIZE)
    if len(data) > 0:
        print("received message: %d, %s" % (len(data), data))