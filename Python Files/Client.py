import time
import serial
import hmac
import hashlib
import radius
import socket
from base64 import b64encode
from base64 import b64decode
from secrets import token_bytes
from secrets import token_bytes
from json import dumps, dump, load, loads
from multiprocessing import Process

# For communication protocols hashes are generated using the sha512 algorithm and "the messages" are encoded and decoded using base64


# Request credentials from the user
IP =  input("Host: ")
Port =  int(input("Port: "))
username = input("Username: ")
secret = input("Secret: ")

password = 'CHAP'

# Creating a new Radius object to communicate with the server
r = radius.Radius(secret, host=IP)

# Creating a function "auth()" that uses the "authenticated" method of the radius 
# object to send an "Access-Request" packet to the server. 
# The "authenticate" method returns the message received from the server and depending 
# on this, the corresponding message is displayed to the user. 
# This function only serves to initialize the communication with 
# the server and receive the final answer.
def auth():
    print("Authenticated" if r.authenticate(username, password) else "Rejected")    

#Creating a process of the "auth" function that is put on hold 
# until the rest of the protocols are executed in "main"
p = Process(target = auth)
p.start()
time.sleep(0.19)

# Creating a variable to store the bounding state between Arduino (PUF)and client
bound_state = False
# Creating a dictionary (CRT2) to store challenge and responses 
# for the bounding stage and for the mutual CHAP
crt2 = {}
 
if __name__ == "__main__":

    # Creating a new communication channel with the program integrated 
    # in the server that moderates the CHAP protocol
    chap_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Starting server authentication")
    chap_client.connect((IP, Port))

    # Sending 'hello' to the chap program to initiate the protocol
    chap_client.sendall(dumps({'type':'hello','data':''}).encode('utf-8'))
    print('Sent hello to server')
    chap_state = False

    # Whille loop to maintain data flow in both directions, 
    # to the PUF and to the chap program
    while not chap_state:
        try:
            # Receiving the message from the chap program
            server_msg = chap_client.recv(2048)
        except Exception as e:
            print ("The Username is wrong")
            server_msg = None
        if not server_msg:
            # Ending the communication if not receiving anything 
            # (by setting the chap_stat to True and therefore ending the while loop)
            chap_state = True
        else:
            # Deserializing the message from the program because 
            # challenges are stored in a JSON file.
            msg = loads(server_msg)
            # Checking if the message has the required type
            if msg['type'] != 'chap_chall':
                print(f'Invalid message type chap_chall: {msg["type"]}')
                print(msg)
            else:
                # Storing the challenge from server to use it after mutual CHAP
                server_challenge = (msg['data'][0])

                # Initializing serial communication with Arduino (PUF) by creating a Serial object
                # At the time of testing the port used was ACM0, 
                # but this must be changed when another port is used
                serial_comm = serial.Serial('/dev/ttyACM0', 9600, timeout=1)
                serial_comm.reset_input_buffer()

                # Setting a variable to store the stage for serial communication
                # and creating a counter to check the number of CRPs for populating the CRT2
                serial_phase = 'start'
                ard_crp_count = 0

                if not bound_state:
                    print('PUF bounding started')
                    # Bounding phase begins to create a new CRT2 for mutual CHAP
                    if serial_phase == 'start':
                        # Creating a loop that runs as many times as desired to create some CRPs for CRT2
                        while (ard_crp_count<3):          
                            serial_phase = 'wait_resp'
                        
                            # Creating a challenge for bounding phase and encoding it in base64
                            bnd_chall = token_bytes(64)
                            bnd_chall_str = b64encode(bnd_chall).decode('utf-8')

                            # Creating the expected response and encoding it
                            bnd_expectd = hashlib.sha512(bnd_chall).digest()
                            bnd_expectd = (b64encode(bnd_expectd).decode('utf-8'))

                            while True:
                                # Sending the message to arduino to communicate the status of the protocol
                                serial_comm.write(b"not_bound\n")
                                serial_comm.write(bnd_chall_str.encode('utf-8'))

                                # Receiving the message from arduino and decoding it
                                ard_line = serial_comm.readline().rstrip()
                                ard_bnd_response = (ard_line).decode('utf-8')
                                ard_bnd_response = b64decode(ard_bnd_response)
                                ard_bnd_response = b64encode(ard_bnd_response).decode('utf-8')

                                # Comparing the Arduino response with the expected one 
                                if ((ard_bnd_response) != None):
                                    if (ard_bnd_response == bnd_expectd):
                                        # If they match, the new CRP is recorded in CRT2 and the counter is incremented
                                        ard_crp_count += 1
                                        crt2[bnd_chall_str] = ard_bnd_response
                                        break
                                    else:
                                        continue
                                else:
                                    continue    
                        # After executing the loop as many times as desired, the bounding phase ends and 
                        # the corresponding variables are modified
                        serial_phase = 'bound'
                        bound_state = True
                        print('Bound Device')

                    # Starting the mutual CHAP protocol between Arduino and client that will use the data from CRP2    
                    print("Starting Mutual CHAP")

                    # Generating a random token that will serve as a random challenge for the first stage of the protocol
                    rand_chall = token_bytes(64)
                    rand_chall_str = b64encode(rand_chall).decode('utf-8')
                    
                    # Extracting a CRP from CRT2
                    crt2_chall_str, crt2_resp_str =  crt2.popitem()
                    crt2_resp_by = b64decode(crt2_resp_str)

                    # Generating the expected message from Arduino using hmac with the sha512 hashing algorithm, 
                    # so the response r1 expected from arduino is resp1 = (crt2_resp, rand_chall)
                    expected = hmac.new(crt2_resp_by, rand_chall_str.encode(), 'sha512')
                    expected = expected.digest()
                    expected = b64encode(expected).decode('utf-8')
                   
                    while True:
                        x = 1
                        while (x < 3):
                            # Sending the protocol status to arduino and then sending the necessary 
                            # data (CRT2 challenge and random challenge) for the first validation performed by client 
                            serial_comm.write(b"R1_incomming\n")
                            serial_comm.reset_input_buffer()
                            serial_comm.write(crt2_chall_str.encode('utf-8'))
                            serial_comm.write(rand_chall_str.encode('utf-8'))
                            serial_comm.reset_input_buffer()

                            # Receiving the r1 response from Arduino
                            resp_from_arduino_by = serial_comm.readline().rstrip()
                            resp1_from_arduino = b64decode(resp_from_arduino_by)
                            resp1_from_arduino = b64encode(resp1_from_arduino).decode('utf-8')
                            if resp1_from_arduino and not resp1_from_arduino.isspace():
                                serial_comm.flush()
                                x = x+ 1   
                            else:
                                continue

                            # If the resp1 message from Arduino matches the locally generated expected response, 
                            # then the protocol status is sent to Arduino
                            while ((expected) == (resp1_from_arduino)):
                                serial_comm.write(b"R2_incomming\n")

                                # The resp2 response is generated using the same method as resp1, but this message must 
                                # be validated by Arduino, similarly how the client validates the Arduino.
                                # The resp2 will be resp2 = (crt2_resp, resp1)
                                resp2_to_arduino = hmac.new(crt2_resp_by, resp_from_arduino_by, 'sha512')
                                resp2_to_arduino = resp2_to_arduino.digest()
                                resp2_to_arduino = b64encode(resp2_to_arduino).decode('utf-8')
                                while True:
                                    # Resp2 is sent to Arduino to be verified with the expected response, generated locally by Arduino
                                    serial_comm.reset_input_buffer()
                                    serial_comm.write(resp2_to_arduino.encode('utf-8'))
                                    serial_comm.reset_input_buffer()
                                    time.sleep(1)
                                    # The Arduino authentication response is received and the corresponding
                                    #  message is displayed, thus ending the mutual CHAP protocol
                                    auth_msg = serial_comm.readline().rstrip()
                                    auth_msg = auth_msg.decode('utf-8')
                                    if auth_msg and not auth_msg.isspace():
                                        serial_comm.flush()
                                    else:
                                        continue
                                    if(auth_msg == "OK"):
                                        print("Done Mutual CHAP")
                                        break
                                    else:
                                        print("Rejected by Arduino")
                                break
                            break
                        break

                
                
                while True:
                    # Sending protocol status to Arduino to be able to switch 
                    # to the normal way of generating responses
                    serial_comm.write(b"not_bound\n")
                    # Sending challenge from server to Arduino
                    serial_comm.write(server_challenge.encode('utf-8'))
                    print('Sending challenge from server to PUF')
                    # Receiving the answer from arduino
                    puf_resp = serial_comm.readline().rstrip()
                    puf_resp = (puf_resp).decode('utf-8')
                    puf_resp = b64decode(puf_resp)
                    puf_resp = b64encode(puf_resp).decode('utf-8')
                    
                    # The final response sent to the authentication program within the server is generated using hmac 
                    # for enhanced security. Thus, secret is used as the key and the sha512 algorithm is used for encryption
                    puf_resp_enc = hmac.new(secret.encode(), puf_resp.encode(), 'sha512')
                    puf_resp_enc = puf_resp_enc.digest()
                    puf_resp_enc = b64encode(puf_resp_enc).decode('utf-8')
                    if ((puf_resp_enc) != None):
                            print("Sending response from PUF to server")
                            break
                    else:
                        continue
                server_response = puf_resp_enc
                print('Server response waiting')
                # At the end, the response is sent to the authentication 
                # program and the communication channel with it is closed
                chap_client.sendall(dumps({'type':'chap_resp','data':server_response}).encode('utf-8'))
    chap_client.close()
    # At this point, the initially started process is resumed, which is related to the method 
    # from the radius object, responsible for the communication.
    # At this point, the authentication message has been returned by the internal authentication 
    # program to the radius server. Resuming the process, the "authenticate" function will return 
    # the message sent by the radius server and the authentication message will be displayed.
p.join()