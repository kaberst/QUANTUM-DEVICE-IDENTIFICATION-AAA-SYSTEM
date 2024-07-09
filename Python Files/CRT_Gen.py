import hashlib
import json
from base64 import b64encode
import secrets


def CRT_gen():
    filename = '/home/kali/Desktop/CRT.json'
    # Deleting all the values in the file except the first one
    with open(filename) as file:
        data = json.load(file)
        k=0
        while(len(data["TABLE"])>1):
            del data["TABLE"][k]
    with open(filename, 'w') as file:
            json.dump(data, file, indent = 4)
    # Generating a new set of challenges-responses and adding them to the file
    # after the first value
    for i in range(0, 100):
        chall = (secrets.token_bytes(64))
        challPush = b64encode(chall).decode('utf-8')
        resp = hashlib.sha512(chall).digest()
        respPush = b64encode(resp).decode('utf-8')
        with open(filename) as file:
            data = json.load(file)
            temp = data["TABLE"]
            store = {"INDEX": i,
                     "CHALLENGE": challPush, 
                     "RESPONSE": respPush
                     }
            temp.append(store)

        with open(filename, 'w') as file:
            json.dump(data, file, indent = 4)
            file.flush()
    # Deleting the first value
    with open(filename) as file:
        data = json.load(file)
        del data["TABLE"][0]
    with open(filename, 'w') as file:
            json.dump(data, file, indent = 4)
            file.flush()
            
if __name__ == '__main__':
    CRT_gen()