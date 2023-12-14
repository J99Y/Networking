"""
    Python 3
    COMP3331 Assignment 
    Author: Alison z5422428
"""
from socket import *
import sys, os
import threading
import time
import json

global activeUserList
activeUserList = []

global clientActive
clientActive =  True

def receive_message(clientSocket):
    while True:
        message = clientSocket.recv(1024)
        response = json.loads(message.decode('utf-8'))

        # store the activeUser for p2p Request
        if response["header"] == "/activeuser" and response["P2P request"] == True:
            # if this is a response for p2p client, send to client
            global activeUserList
            activeUserList = response["returnMsg"]
            continue
        # if the msg is a list, print each line
        if type(response["returnMsg"]) == type(list()):
            for item in response["returnMsg"]:
                print(item)
        else:
            print(response["returnMsg"])
        print("\n\n > ", end="")


# this method will send the message to the server and go through the authentication process
def serverAuthentication(username, password, clientSocket):
    message = username + " " + password + '\n'
    request = {
        "username" : username,
        "password" : password
    }
    clientSocket.send(bytes(json.dumps(request),encoding='utf-8'))
    response = clientSocket.recv(1024)
    isAuthenticate = json.loads(response.decode('utf-8'))
    return isAuthenticate


def connectServer(host, serverPort, udpPort):
    # define a socket for the client side, it would be used to communicate with the server
    clientSocket = socket(AF_INET, SOCK_STREAM)
    serverAddress = (host, serverPort)

    # build connection with the server and send message to it
    clientSocket.connect(serverAddress)
    start = True
    validityUser = False
    print("Please login")
    while True:
        if start:
            request = {
                "command" : "authentication"
            }
            clientSocket.sendall(bytes(json.dumps(request),encoding='utf-8'))
            start = False
        # receive response from the server
        # 1024 is a suggested packet size, you can specify it as 2048 or others
        data = clientSocket.recv(1024)
        response = json.loads(data.decode('utf-8'))
        
        # parse the message received from server and take corresponding actions
        if response["request"] == "":
            print("[recv] Message from server is empty!")
        elif response["request"] == "user credentials request":
            # get the username and password from the user
            isAuthenticate = "[Invalid]"
            # keep asking for username & password for login
            if isAuthenticate == "[Invalid]": 
                if validityUser == False:
                    username = input("Username: ")
                password = input("Password: ")
                # go through authentication process
                isAuthenticate = serverAuthentication(username, password, clientSocket)
                print(isAuthenticate["returnMsg"])
                # shut down terminal if the user is blocked
                if "[Blocked]" in isAuthenticate["returnMsg"]:
                    # close the socket
                    clientSocket.close()
                    exit()
                elif "Invalid Password" in isAuthenticate["returnMsg"]:
                    validityUser = True
    
                if isAuthenticate["statusCode"] == "200":
                    # user has successful login = send UDP port to server
                    request = {
                        "command": "logging",
                        "udpPort": udpPort
                    }

                    clientSocket.send(bytes(json.dumps(request),encoding='utf-8'))
                    # open udp  client sercer
                    udpServer(udpPort, clientSocket, username)
                    
                    break
        else:
            print("[recv] Message makes no sense")

    t1 = threading.Thread(target=receive_message, args=(clientSocket,))
    t2 = threading.Thread(target=receive_command, args=(clientSocket, username))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    print("socket is closing")
    # close the socket
    clientSocket.close()

# create Json format request
def createRequest(request, nameType, infoType, message):
    try:
        request[nameType] = message.split()[1]
    except Exception:
        request[nameType] = False
    try:
        request[infoType] = message.split()[2:]

        if not request[infoType]:
            request[infoType] = False
    except Exception:
        request[infoType] = False
    return request

def receive_command(clientSocket, username):
    while True:
        print("Enter one of the following commands (/msgto, /activeuser, /creategroup, /joingroup, /groupmsg, /p2pvideo, /logout):")
        # getting the command
        message = input("> ")
        
        request = {
            "command": message.split()[0]
        }

        if request["command"] == "":
            print("[recv] Message from user is empty!")

        elif request["command"] == "/msgto":
            # private message, which the user lauches private chat with another active user and send private message
            print("[recv] msgto")
            request = createRequest(request, "receiver", "message", message)

        elif request["command"] == "/activeuser":
            print("[recv] activeuser")
            request["P2P request"] = False

        elif request["command"] == "/creategroup":
            print("[recv] creategroup")
            request = createRequest(request, "groupname", "userList", message)

        elif request["command"] == "/joingroup":
            print("[recv] joingroup")
            try:
                request["groupname"] = message.split()[1]
            except Exception:
                request["groupname"] = False
            # clientSocket.send(message.encode())

        elif request["command"] == "/groupmsg":
            print("[recv] groupmsg")
            request = createRequest(request, "groupname", "message", message)
        
        elif request["command"] == "/p2pvideo":
            # 1. Check argument
            if len(message.split()) < 3:
                print("[Error] Usage: /p2pvideo username filename")
                continue
            request["receiver"] = message.split()[1]
            request["filename"] = message.split()[2]
            sendVideo(clientSocket, request, username)
            continue
            time.sleep(2)
            # clientSocket.send(message.encode())
        elif request["command"] == "/logout":
            print("[recv] logout")
            print(f"Goodbye {username} !!!")
            clientSocket.send(bytes(json.dumps(request),encoding='utf-8'))
            clientSocket.close()
            clientActive = False
            os._exit(1)
        else:
            print("[Error] Command not make sense")
            continue
        # send the message to the server
        clientSocket.send(bytes(json.dumps(request),encoding='utf-8'))
        time.sleep(0.5)

# Establish udp Server for P2P communication
def udpServer(udpPort, clientSocket, username):
    # get the hosename of the client(server)
    hostname = gethostname()
    host = gethostbyname(hostname)
    
    # open another socket for UDP server (Audience)
    serverSocket = socket(AF_INET, SOCK_DGRAM)
    serverSocket.bind((host, udpPort))
    t3 = threading.Thread(target=recvVideo, args=(serverSocket, clientSocket,))
    t3.start()


def recvVideo(serverSocket, clientSocket):
    while clientActive:
        # read 1024 byte at a time
        buf = 2048
        data,addr = serverSocket.recvfrom(buf)
        message = json.loads(data.decode('utf-8'))
        sender = message["sender"]
        filename = message['filename']
        if os.path.exists(filename):
            print("[Error] already receive this file")
            time.sleep(5)
            continue
        
        print(f" Received File Info : {filename}\n Downloading...")
        dataQueue = []

        # open the file for reading
        f = open(filename,'wb')
        
        data,addr = serverSocket.recvfrom(buf)
        byteReceived = 0
        try:
            while(data):
                byteReceived += 2048
                f.write(data)
                serverSocket.settimeout(5)
                data,addr = serverSocket.recvfrom(buf)
        except timeout:
            f.close()
            print("File Downloaded")
        print(f"File Has Successfully Downloaded")

def sendVideo(clientSocket, msg, username):

    # check if user is valid - sending /activeuser to 
    request = {
        "command": "/activeuser",
        "P2P request": True
    }
    # sending /activeuser request
    clientSocket.send(bytes(json.dumps(request),encoding='utf-8'))
    time.sleep(1)
 
    # check if receiver is active
    isActive = False

    for line in activeUserList:
        user = line.split(", ")[0].strip()
        if user == msg["receiver"]:
            isActive = line
    # if the user is active
    if isActive != False:
        # obtain the address and UDP server port
        address = isActive.split("[")[1].split("]")[0]
        udpPort = isActive.split("[")[2].split("]")[0]
       
        # send some info to the receiver indicate sender and total byte
        info = {
            "sender": username,
            "filename": f"{msg['receiver']}_{msg['filename']}",
            "size": os.stat(msg["filename"]).st_size
        }

        # transfer the file using UDP
        print("Sending video..")
        # create the socket
        s = socket(AF_INET,SOCK_DGRAM)
        hostname = gethostname()
        host = gethostbyname(hostname)
        port = int(udpPort)
        addr = (host, port)
        info = bytes(json.dumps(info),encoding='utf-8')
        # send the info the client Audience - info of the file
        s.sendto(info,addr)
        time.sleep(1)
        try:
            f = open(msg["filename"],"rb")
        except Exception:
            print(f"[Error] The file: {msg['filename']} does not exist")
            return
        data = f.read(2048)

        while (data):
            if(s.sendto(data,addr)):
                time.sleep(1)
                data = f.read(2048)
        s.close()
        f.close()
        print(f"{msg['filename']} is uploaded")

    else:
        print(f"[Error] The username: {msg['receiver']} is not active")




if __name__ == '__main__':
    if len(sys.argv) != 4:
        print('Error: insufficient argument <host> <port> <UDP port>')
        exit(1)
    # host = server
    host = sys.argv[1]
    serverPort = int(sys.argv[2])
    # UDP port is for client-client (P2P) connection
    udpPort = int(sys.argv[3])
    connectServer(host, serverPort, udpPort)
