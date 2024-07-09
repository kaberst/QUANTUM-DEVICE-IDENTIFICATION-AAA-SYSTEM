import sys
import hmac
import socket
import hashlib
import json
import random
from json import dumps, dump, load, loads
from secrets import token_bytes
from base64 import b64encode, b64decode

# Setting paths for the files to be used, respectively the file in 
# which the CRT is stored and the file with users' credentials
crt_file ='/home/kali/Desktop/CRT.json'
users_file = '/home/kali/Desktop/USERS.json'

#ip = sys.argv[4]

#The IP set address must be the address on which the Radius server is running
ip = "10.34.194.243"

# The port must be the one the server is listening on and must match the type of action 
# that will be performed on it (e.g. 1812 for authentication). This port will also be for 
# direct connection to the client and this means that it must be opened in the firewall
port = 1812

# The username will be sent by the freeRADIUS server as an argument
username = sys.argv[1]

# The function that will moderate the CHAP protocol is created
def CHAP_Authenticator():
    # A random index is generated to be used to extract CRPs from CRT
    random_index = random.randint(0,100)

    # A new communication channel is created with the client to 
    # send challenges and receive responses; 
    # respectively by creating a new socket object for "the server"
    chap_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    chap_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Associating the created socket with the desired interface and port, 
    # and enabling the server to accept connections
    chap_server.bind((ip,port))
    chap_server.listen(1)

    # A loop is used to keep the "server" open until the response is received from the client
    srv_close = False
    while not srv_close:

        # Creating a new socket object that is connected to the server socket; 
        # this new socket serves to send messages to the connecting client
        client, addr = chap_server.accept()
        conn_close = False
        state = 'start'
        expected = 0x00

        # Creating a loop that runs as long as it is necessary to communicate with the client,
        # at the end of it closing the connection
        while not conn_close:
            try:
                # Receiving data sent by the client
                data = client.recv(2048)
            except Exception as e:
                print (e)
                data = None
            if not data:
                conn_close = True
            else:
                # Decoding the message and checking 
                # if it is the message type to initiate the CHAP protocol
                msg = loads(data.decode('utf-8'))
                if state == 'start':
                    if msg['type'] != 'hello':
                        print ('Reject')
                    else:
                        # Starting the stage of extracting a new CRP and setting the variable "state" for 
                        # the next stage, respectively for waiting for the answer from the client
                        state = 'wait_resp'

                        # Extracting a challenge from the CRT that is stored in the JSON file; 
                        # the extraction is done using the random index generated at the beginning
                        with open(crt_file, 'r') as file:
                            k = file.read()
                            mains = json.loads(k)
                            crt_chall = (mains['TABLE'][random_index]['CHALLENGE'])

                        # The extraction operation is repeated to get a response
                        with open(crt_file, 'r') as file:
                            k = file.read()
                            mains = json.loads(k)
                            crt_resp = (mains['TABLE'][random_index]['RESPONSE'])   

                            # The expected response from the client is generated; it is generated using hmac with the sha512 algorithm, 
                            # and the key used for encryption is the secret corresponding to the user trying to authenticate 
                            expected = hmac.new(user_secret.encode(), crt_resp.encode(), 'sha512')
                            expected = expected.digest()
                            expected = b64encode(expected).decode('utf-8')

                        # The challenge from CRT is sent to the client
                        client.send(dumps({'type':'chap_chall', 'data':[crt_chall]}).encode('utf-8'))
                
                # Moving on to the next stage in which the response is expected from the client
                elif state == 'wait_resp':
                    # The type of date the client sends is checked
                    if msg['type'] != 'chap_resp':
                        print ('Reject')
                    else:
                        # The response is decoded and compared to
                        # the previously generated expected response
                        resp = b64decode(msg['data'].encode('utf-8'))
                        resp = b64encode(resp).decode('utf-8')

                        # If the responses match, the message "Accept" is printed and is recorded in the "Auth-Type" 
                        # argument in the configuration file of the freeRadius server. When the authentication is verified, 
                        # the server has registered the message "Accept" and will allow the user to authenticate
                        if resp == expected:
                            print ('Accept')
                            
                            # A new challenge is generated using a 64-byte random token, and the sha512 hasing algorithm 
                            # is used to generate the response, which is also used by Arduino to generate the responses
                            chall = token_bytes(64)
                            challPush = b64encode(chall).decode('utf-8')
                            resp = hashlib.sha512(chall).digest()
                            respPush = b64encode(resp).decode('utf-8')

                            # The newly generated CRP replaces the CRP used for the authentication that took place. 
                            # Thus, the challenge and the response generated are placed in the JSON file, using 
                            # the corresponding index used previously to extract the used CRP
                            with open(crt_file) as file:
                                data = json.load(file)
                                data['TABLE'][random_index]['CHALLENGE'] = challPush
                                data['TABLE'][random_index]['RESPONSE'] = respPush

                            with open(crt_file, 'w+') as file:
                                json.dump(data, file, indent = 4)
                                file.flush()

                        else:
                            print ('Reject')

                            # If a user is rejected, the same procedure is followed and 
                            # the CRP used is replaced with a newly generated one
                            chall = token_bytes(64)
                            challPush = b64encode(chall).decode('utf-8')
                            resp = hashlib.sha512(chall).digest()
                            respPush = b64encode(resp).decode('utf-8')

                            with open(crt_file) as file:
                                data = json.load(file)
                                data['TABLE'][random_index]['CHALLENGE'] = challPush
                                data['TABLE'][random_index]['RESPONSE'] = respPush

                            with open(crt_file, 'w+') as file:
                                json.dump(data, file, indent = 4)
                                file.flush()

                        # Thus, using the same algorithm (both for server and Arduino) to generate 
                        # the response simulates the use of a PUF, only in the case presented CRT is built by the server. 
                        # In a real situation, instead of generating new CRPs, CRPs from the CRT provided by the PUF manufacturer
                        # would be used, and at the end of authentication that used CRP would be deleted from the CRT.


                        conn_close = True
                        srv_close = True

        # The connection with the client is closed and then the server is closed
        client.close()

    chap_server.close()
   
if __name__ == "__main__":

    # The JSON file with credentials is opened
    with open(users_file, 'r') as file:
        k = file.read()
        items = json.loads(k)

        # The argument sent by the server is used to search the JSON file
        user = str(username)

        # A username search function is created to search the json file with user credentials
        # If the name is found, the secret corresponding to the user is returned, a secret that 
        # will be used as key to generate the expected response
        def search_user (name):
            for keyval in items:
                if name.lower() == keyval['NAME'].lower():
                    return keyval['SECRET']
        # If the search function returns a value (i.e. the user is found in the file),
        # then the value returned (the secret) is stored in a variable that will be used 
        # to generate the expected response and then the function that moderates the authentication 
        # protocol is called
        if (search_user(user) != None):
            user_secret = search_user(user)
            CHAP_Authenticator();
        else:
            # If the username is not found in the file, then the message "Reject" 
            # is returned to the server and the authentication attempt will be rejected
            print ('Reject')