#coding: utf-8
from socket import *
import sys, re, json
from threading import Thread
import time
import select
from datetime import datetime


# Declare global variable
global trail
global port
global host

# contain all the valid user {username: password}
global validUser
validUser = {}
# record number of fail attempts of each user
global failDict 
failDict = {}
# record the block time for each user {username: end of block time}
global blockUser
blockUser = {}
global BLOCKTIME
BLOCKTIME = 10
# storing the {username : the client socket}
global activeUser
activeUser = {}
# groupDict => groupname: [{user1:isJoin}]
global groups
groups= {}

def authentication(httpRequest):
    # get the username
    username = httpRequest["username"]
    response = {
        "statusCode" : 400
    }
    # check if username is in the credentials.txt
    # if not isValidUser(username, lines):
    if username not in validUser:
        response["returnMsg"] = "[Invalid] Invalid Username"
        return response
    elif username in activeUser:
        response["returnMsg"] = f"[Invalid] {username} has already login on other terminal"
        return response

    # check if the user is blocked before / still blocking
    if username in blockUser:
        timenow = datetime.now()
        timeblocked = blockUser[username]
        blockedTime = timenow - timeblocked
        # make sure the user is blocked for 10s
        if blockedTime.total_seconds() < BLOCKTIME:
            msg = "[Blocked] Your account is blocked due to multiple login failures. Please try again later"
            response['returnMsg'] = msg
            return response
        else:
            blockUser.pop(username)
            failDict.pop(username)

    # check if the password is correct
    if httpRequest["password"] != validUser[username]:
        # Wrong password : increase fail 
        if username in failDict:
            failDict[username] += 1
        else:
            failDict[username] = 1
        print(failDict)
        # if the user have consecutive fail exceed the limit
        if failDict[username] == trail - 1:
            # Block the user
            blockUser[username] = datetime.now()
            response['returnMsg'] = "[Blocked] Invalid Password. Your account has been blocked. Please try again later"
        
        response['returnMsg'] = "[Invalid] Invalid Password. Please try again"
    else:
        # correct login
        failDict[username] = 0
        activeUser[username] = len(activeUser) + 1
        response = {
            "statusCode": "200",
            "returnMsg": "Welcome to TESSENGER!"
        }
        
    return response


# Function to log a message to a user's log file
def log_user(username, timestamp, clientIP, udpPort):
    # Open the user's log file in append mode or create one
    log_file = "userlog.txt"
    seqNumber = getFileLen(log_file) + 1
    # log the user to the file
    with open(log_file, "a") as file:
        file.write(f"{seqNumber}; {timestamp}; {username}; {clientIP}; {udpPort}\n")

# append msg to a given filename
def logFile(filename, msg):
    with open(filename, "a") as f:
        f.write(msg)

# get the total length of a given filename
def getFileLen(filename):
    with open(filename, "r") as fp:
        lines = fp.readlines()
        return len(lines)

# check all the username in the list is active
def isUserValid(usernameList):
    for user in usernameList:
        if user not in activeUser:
            return False
    return True

# Remove deactive username from the userlog.txt
def updateActiveFile(username):
    # get all the lines in the userlog.txt
    with open("userlog.txt", "r") as f:
        lines = f.readlines()
    # delete all info in the userlog.txt
    f = open("userlog.txt", "w")
    f.close

    for line in lines:
        info = line.split("; ")
        # get all the info exclude the username
        if info[2] == username:
            continue
        log_user(info[2], info[1], info[3], info[4].strip())
    

# initialise all the file and store validUser info
def initialise():
    f = open("userlog.txt", "w")
    f.close()
    f = open("messagelog.txt", "w")
    f.close()
    # get all the valid user into the dict
    file = open('credentials.txt', 'r')
    lines = file.readlines()
    for line in lines:
        name = line.split()[0]
        password = line.split()[1]
        validUser[name] = password
    file.close()

def getTimeStamp():
    return datetime.now().strftime('%d %b %Y %H:%M:%S')

# create SMTP message format
def createMailMessage(sender, receiver, messageType, msg):
    sendMsg = {
        "header" : {
            "To": receiver,
            "From": sender,
            "subject": messageType
        },
        "returnMsg": f"[Recv] {msg}"
    }
    return sendMsg

"""
    Define multi-thread class for client
    This class would be used to define the instance for each connection from each client
    For example, client-1 makes a connection request to the server, the server will call
    class (ClientThread) to define a thread for client-1, and when client-2 make a connection
    request to the server, the server will call class (ClientThread) again and create a thread
    for client-2. Each client will be runing in a separate therad, which is the multi-threading
"""
class ClientThread(Thread):
    
    def __init__(self, clientAddress, clientSocket):
        Thread.__init__(self)
        self.clientAddress = clientAddress
        self.clientSocket = clientSocket
        self.clientAlive = False
        self.username = ""
        print("===== New connection created for: ", clientAddress)
        self.clientAlive = True
        
    def run(self):
        message = ''
        
        while self.clientAlive:
            # use recv() to receive message from the client
            data = self.clientSocket.recv(1024)
            # if the error, continue            
            try:
                httpRequest = json.loads(data.decode('utf-8'))
            except Exception:
                httpRequest["command"] == ""

            response = {
                "header": httpRequest["command"],
                "statusCode": 500
            }
            # if the message from client is empty, the client would be off-line then set the client as offline (alive=Flase)
            if httpRequest["command"] == '':
                self.clientAlive = False
                activeUser.pop(self.username)
                print(f"{self.username} logout")

                print("===== the user disconnected - ", clientAddress)
                break
            # handle httpRequest["command"] from the client
            if httpRequest["command"] == 'authentication':
                print("[recv] New login request")
                # authenticate process
                self.process_login()

            elif httpRequest["command"] == "logging":
                # log the user : timestamp, self.username, IP address, port number
                activeSeq = activeUser[self.username]
                udpPort = httpRequest["udpPort"]
                # get current timestamp
                timestamp = datetime.now().strftime('%d %b %Y %H:%M:%S')
                log_user(self.username, timestamp, host, udpPort)
                with open("userlog.txt", "r") as fp:
                    lines = fp.readlines()
                
            elif httpRequest["command"] == "/msgto" :

                print("[recv] Private Message sending")

                # get the receiver & Message
                receiver = httpRequest["receiver"]
                msg = httpRequest["message"]
                # check if argument are valid
                if receiver == False or msg == False:
                    response["returnMsg"] ="[Error] Please indicate which user you want to send"
                    print(response["returnMsg"])
                    self.clientSocket.send(bytes(json.dumps(response),encoding='utf-8'))
                    continue

                msg = " ".join(msg)
                 # check if the receiver is in the active list
                if receiver not in activeUser:
                    response["returnMsg"] = f"[Error] the receiver: {receiver} is not valid, Can't send the message"
                    
                    self.clientSocket.send(bytes(json.dumps(response),encoding='utf-8'))
                    print(response["returnMsg"])
                    continue

                # get current timestamp
                timestamp = datetime.now().strftime('%d %b %Y %H:%M:%S')
            
                # print the message into the messagelog.txt
                msgNumber = getFileLen("messagelog.txt") + 1

                # log message to file
                with open("messagelog.txt", "a") as file:
                    file.write(f"{msgNumber}; {timestamp}; {receiver}; {msg}\n")
           
                # Receiver: send a message to the receiver
                receiverSocket = activeUser[receiver]
                msg = f"{timestamp}; {self.username}; {msg}"
                sendMsg = createMailMessage(self.username, receiver, "Private Message", msg)
                    
                activeUser[receiver].send(bytes(json.dumps(sendMsg),encoding='utf-8'))

                # Sender: send back message to Sender with the timestamp
                response = {
                        "header": httpRequest["command"],
                        "statusCode" : "200",
                        "returnMsg" : f"[Send] message send at {timestamp}.\n"
                    }
                    
                self.clientSocket.send(bytes(json.dumps(response),encoding='utf-8'))
                print(f"{self.username} message to {receiver} \"{msg}\" at {timestamp}")

            elif httpRequest["command"] == "/activeuser":
                print("[Recv] activeuser" )
                # printing message for the server
                print(f"{self.username} issued /activeuser command\n Return messages:")
                # 1. check if there are any other active user i.e activeUser > 1
                if len(activeUser) == 1:
                    msg = "no other active user\n"
                    # no other active user
                    response = {
                    "header": httpRequest["command"],
                    "statusCode" : "400",
                    "returnMsg" : msg,
                    "P2P request": httpRequest["P2P request"]
                }
                    print(msg)
                    self.clientSocket.send(bytes(json.dumps(response),encoding='utf-8'))
                    continue

                # 2. open the file and get all the info
                with open("userlog.txt","r") as fp:
                    # 2.1 exclude the user that send the email
                    lines = fp.readlines()
                returnList = []

                for line in lines:
                    # exclude the sender
                    if f" {self.username};" not in line:
                        # get each info from the line
                        info = line.split(";")
                        timestamp = info[1]
                        name = info[2]
                        clientIPAddress = info[3]
                        udpPortListen = info[4]
                        msg = f"{name}, active since {timestamp}, listening the Ip Address of [{clientIPAddress}] in UDP port [{udpPortListen.strip()}]"
                        # put into a list for printing later on the server
                        returnList.append(msg)

                response = {
                    "header": httpRequest["command"],
                    "statusCode" : "200",
                    "returnMsg" : returnList,
                    "P2P request": httpRequest["P2P request"]
                }
                

                # return the each activeuser to the client
                self.clientSocket.send(bytes(json.dumps(response),encoding='utf-8'))
                for line in returnList:
                    print(line)

            elif httpRequest["command"] == "/creategroup":

                print(f"{self.username} issued /creategroup command")
                print("> Return message: ")

                # if no groupname or userList input
                if httpRequest["groupname"] == False or httpRequest["userList"] == False:
                    msg = f"[Error] Please enter at least one more active users\n"
                    response["returnMsg"] = msg
                    self.clientSocket.send(bytes(json.dumps(response),encoding='utf-8'))
                    print(f"Group chat room is not created. {msg}")
                    continue

                if not isUserValid(httpRequest["userList"]):
                    msg =  "[Error] Username is not valid, No Group create\n"
                # 2. Check if the httpRequest["groupname"] is uniq and consist latter and digit
                elif re.match("^[a-zA-Z0-9]*$", httpRequest["groupname"]) == None:
                    msg = "[Error] Groupname is not valid\n"
                  
                elif httpRequest["groupname"] in groups:
                    msg = f"[Error] A group chat (Name: {httpRequest['groupname']}) already exist\n"
                
                else:
                    # 3. create a log file for the group
                    f = open(f"{httpRequest['groupname']}_messageLog.txt", "w")
                    f.close()
                    # 4. store group chat member
                    usernameInfo = {}
                    for member in httpRequest["userList"]:
                        usernameInfo[member] = False
                    # the creator automatically join the group
                    usernameInfo[self.username] = True
                    groups[httpRequest["groupname"]] = usernameInfo
                    
                    # 5. Server reply to the client to confirm the group chat room has maded
                    httpRequest["userList"] = ", ".join(httpRequest['userList'])
                    msg = f"Group chat room has been created, room name: {httpRequest['groupname']}, users in this room: {httpRequest['userList']}\n"
                    response = {
                        "header": httpRequest["command"],
                        "statusCode": 200
                    }

                response["returnMsg"] = msg
                self.clientSocket.send(bytes(json.dumps(response),encoding='utf-8'))
                        
                print(f"{msg}")

            elif httpRequest["command"] == "/joingroup":
                print(f"> {self.username} issued /joingroup command")
                print("Return message: ")

                # check if has input
                if not httpRequest["groupname"]:
                    msg = f"[Error] Please specific which group to join"
                    print(f"> {msg}")
                # 1. check if the group name exist
                elif httpRequest["groupname"] not in groups:
                    msg = f"[Error] Name: {httpRequest['groupname']} hasn't created"
                    print(f"> {msg}")
                # 2. check if the user is initial added to the group
                elif self.username not in groups[httpRequest["groupname"]]:
                    msg = f"[Error] User: {self.username} is not inital added to the group"
                    print(f"> {msg}")
                elif groups[httpRequest["groupname"]][self.username] == True:
                    msg = f"[Error] User: {self.username} You have already join the group"
                    print(f"> {self.username} tries to re-join to a group chat {httpRequest['groupname']}")
                # The user join the group
                else:
                    groups[httpRequest["groupname"]][self.username] = True
                    userList = groups[httpRequest["groupname"]].keys()
                    userList = ", ".join(userList)
                    msg = f"Join group chat room successfully, room name: {httpRequest['groupname']}, users in this room {userList}"
                    print(f"> {msg}")
                    response = {
                        "header": httpRequest["command"],
                        "statusCode": 200
                    }
                response["returnMsg"] = msg
                self.clientSocket.send(bytes(json.dumps(response),encoding='utf-8'))
                

            elif httpRequest["command"] == "/groupmsg":
                print(f"{self.username} issued /groupmsg")
                # 1. check if argument is valid:
                if not httpRequest["groupname"] or not httpRequest["message"]:
                    msg =  "[Error] Please give a groupname and a message"
                    response["returnMsg"] = msg
                    print(msg)
                    self.clientSocket.send(bytes(json.dumps(response),encoding='utf-8'))

                    continue
                
                # get the variable from the request
                groupname = httpRequest["groupname"]
                message = " ".join(httpRequest["message"])
                print(f"{self.username} issued a message in group chat {groupname}:")
                
                # 1. if the group exist
                if groupname not in groups:
                    msg = "[Error] The group chat name does not exit"
                   
                # 2. check if client is in the group
                elif self.username not in groups[groupname]:
                    msg = "[Error] You are not in this group chat"
                # 3. check if the client has join the group
                elif groups[groupname][self.username] == False:
                    msg = "[Error] Please join the group before sending message"
                    print(f"> [Error] {self.username} send a message to a groupchat, but {self.username} hasn't joined")
                else :
                    # 4. Add the msg to messagelog.txt
                    timestamp = getTimeStamp()
                    msgNumber = getFileLen(f"{groupname}_messageLog.txt") + 1

                    # 5. send a confirmation message to the user
                    msg =  "Group chat message send"
                    # 6. forward message to all active group memher
                    for member in groups[groupname]:
                        if member == self.username:
                            continue
                        if groups[groupname][member] and activeUser[member]:
                            # msg send using SMTP
                            msg = f"{timestamp}; {groupname}; {self.username}: {message}\n"
                            sendMsg = createMailMessage(self.username, member, groupname, msg)
                            activeUser[member].send(bytes(json.dumps(sendMsg),encoding='utf-8'))
                    msg = f"#{msgNumber}; {msg}\n"
                    logFile(f"{groupname}_messageLog.txt", msg)
                    response["statusCode"] = "200"
                response["returnMsg"] = msg
                print(f"> {msg}")
                self.clientSocket.send(bytes(json.dumps(response),encoding='utf-8'))

            elif httpRequest["command"] == "/logout":
                self.process_logout(self.username)
            else:
                print("[recv] " + message)
                print("[send] Cannot understand this message")
                response = {
                    "header": httpRequest["command"],
                    "statusCode": "400",
                    "resturnMsg": "Cannot understnad this message"
                }
                self.clientSocket.send(bytes(json.dumps(response),encoding='utf-8'))
            print()
    
    def process_logout(self, username):
        updateActiveFile(username)
        self.clientAlive = False
        activeUser.pop(self.username)
        print(f"{self.username} logout")

        print("===== the user disconnected - ", clientAddress)

    def process_blocked(self, username):
        self.clientAlive = False
        print(f"{username} is blocked, Login Later")

    def process_login(self):
        while True:
            # prompt the user to give self.username and password
            message = 'user credentials request'
            request = {
                "request" : message
            }
            print('[send] ' + message)
            # request user 
            self.clientSocket.send(bytes(json.dumps(request),encoding='utf-8'))
            data = self.clientSocket.recv(1024)
            try:
                httpRequest = json.loads(data.decode('utf-8'))
            except Exception:
                self.process_blocked(httpRequest["username"])
                break

            # go for authenticate process
            isAuthenticate = authentication(httpRequest)
            self.clientSocket.send(bytes(json.dumps(isAuthenticate),encoding='utf-8'))
            # if the authentication process pass
            if "[Invalid]" not in isAuthenticate["returnMsg"] and "[Blocked]" not in isAuthenticate["returnMsg"]:
                # go for log the function
                self.username = httpRequest["username"]
                timestamp = datetime.now().strftime('%d %b %Y %H:%M:%S')
                activeUser[self.username] = self.clientSocket
                print(f"{self.username} login successfully\n")
                break

            time.sleep(0.1)
            

if __name__ == "__main__":
    # acquire server host and port from command line parameter
    if len(sys.argv) != 3 :
        print("Error: Port number, Max Trial")
        exit(1)
    port = int(sys.argv[1])
    # get the number of trial 
    trail = int(sys.argv[2])
    # must be integer between 1-5
    trail_range = range(1,6)
    if trail not in trail_range:
        print(f"Invalid number of allowed failed consecutive attempt: {trail}")
        exit(1)
    # get the information of the server
    hostname = gethostname()
    host = gethostbyname(hostname)
    serverAddress = (host, port)
    initialise()
    # define socket for the server side and bind address
    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.bind(serverAddress)

    print("\n===== Server is running =====")
    print("===== Waiting for connection request from clients...=====")
    print(f"TCP Server working on {host}:{port}, Ready to Receive")

    while True:
        serverSocket.listen()
        clientSockt, clientAddress = serverSocket.accept()
        clientThread = ClientThread(clientAddress, clientSockt)
        clientThread.start()
