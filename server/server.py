import base64
import random
import socket
import string
import threading
import hashlib
from pathlib import Path
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import parser
from request import Request
from consts import RequestCode
from data_base import PrjDataBase
from response import ResponseReceivedFile, ResponseReceivedMes, ResponseRegistrationFail, \
    ResponseRegistrationSucceeded, ResponseReceivedPublicKeySendPrivateAES

HOST = '127.0.0.1'
DEFAULT_PORT = 1234


# open the server and send every client connection request to single thread.
def open_the_server():
    port = read_port()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, port))
        s.listen()
        print('[+] Whiting for connection on : ' + str(HOST) + ', port: ' + str(port))
        while True:
            # accept any connection and open new thread to serve this client.
            connection, address = s.accept()
            print('[+] Connected by: ', address)
            client_connection = threading.Thread(target=connect_with_client, args=(connection,))
            client_connection.start()


# connection with client
def connect_with_client(connection):
    # connect to database
    data_base = PrjDataBase(name="server.db")
    # if fail to open database return
    if data_base.create_and_open() == 0:
        print("[-] Error: connection to database fail!")
        return -1
    keep_alive = True
    while keep_alive:
        # get data from client until \x00 (EOF)
        fragments = []
        while True:
            chunk = connection.recv(1024)
            if chunk == b'\x00':
                break
            fragments.append(chunk)
        recv_data = bytearray(b''.join(fragments))

        # create and Request obj and parse data
        try:
            client_req = Request(bytes_request=recv_data)
        except Exception as e:
            print("[-] Error: Invalid request content: " + str(e))
            return -1
        print("[+] get request: " + str(client_req.code))

        match client_req.code:
            case RequestCode.REGISTRATION:
                # registration for new user, get client id.
                client_id = registration(client_req=client_req, data_base=data_base)
                if client_id == 0:
                    # registration fail, exit from loop
                    res = ResponseRegistrationFail()
                    keep_alive = False
                else:
                    res = ResponseRegistrationSucceeded(client_id=client_id)
            case RequestCode.SEND_PUBLIC_KEY:
                # create new AES key for encryption, return the kay and encrypted key.
                aes_key, aes_encrypted = aes_create(client_req=client_req, data_base=data_base)
                res = ResponseReceivedPublicKeySendPrivateAES(client_id=client_req.client_id, key_aes=aes_encrypted)
            case RequestCode.SEND_FILE:
                # decrypt the file, save to "files" folder, save file info in database, calculate and return the cksum of the file
                check_sum = handling_the_file(client_req=client_req, aes_key=aes_key, data_base=data_base)
                res = ResponseReceivedFile(client_id=client_req.client_id, content_size=client_req.payload.content_size,
                                           file_name=client_req.payload.file_name, crc=check_sum)
            case RequestCode.CRC_OK | RequestCode.CRC_ERROR:
                # the last message get from client
                res = ResponseReceivedMes()
                keep_alive = False
                # get CRC_OK message -> update files database that the file verified.
                if client_req.code == RequestCode.CRC_OK:
                    data_base.set_verified_file(file_name=client_req.payload.file_name)

        # build the byte response and send Response to client
        byte_response = res.build_response()
        send_data = bytearray(1024)
        parser.copy_byte_arr_to_byte_arr(from_byte_arr=byte_response, to_byte_arr=send_data, to_ind=0)
        connection.sendall(send_data)
        print("[+] response: " + str(res.code) + " sent to the client!")

    data_base.close()
    print("[!] socket close!")


# read port from file "port.info"
# if file not exist return default port
def read_port():
    try:
        with open('port.info', 'r') as f:
            port = int(f.readline())
            return port
    except Exception as e:
        print("[-] Error while reading port number: " + str(e))
        return DEFAULT_PORT


# registration for new user.
def registration(client_req: Request, data_base: PrjDataBase):
    name = client_req.payload.name
    # if user already exist in database return error
    if data_base.check_if_user_name_exist(name=name):
        print('[-] user already exist. registration fail!')
        return 0
    else:
        # generate user id, and add user info to database
        user_id = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        data_base.add_user(name=name, user_id=user_id)
        print('[+] registration completed!')
        return user_id


# create new AES key for encryption, return the kay and encrypted key.
def aes_create(client_req: Request, data_base: PrjDataBase):
    client_id = client_req.client_id
    pub_key = client_req.payload.public_key
    # create AES key
    aes_key = get_random_bytes(16)
    # encrypt the AES kay with the public key get from client
    cipher = PKCS1_OAEP.new(RSA.importKey(base64.b64decode(pub_key)))
    aes_encrypted = cipher.encrypt(aes_key)
    # write the AES key to database.
    data_base.set_keys(client_id=client_id, pub_key=pub_key, aes_key=aes_key)
    return aes_key, aes_encrypted


# decrypt the file, save to "files" folder, save file info in database, calculate and return the cksum of the file
def handling_the_file(client_req: Request, aes_key, data_base: PrjDataBase):
    file = client_req.payload.message_content
    file_name = client_req.payload.file_name
    # decryption
    iv = ('\0' * 16).encode()
    ct = file
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    file_decrypted = cipher.decrypt(ct)
    padding_bytes = file_decrypted[-1]
    file_decrypted = file_decrypted[:-padding_bytes]
    # save the file in files folder
    Path("files").mkdir(parents=True, exist_ok=True)
    path = "files/" + file_name
    with open(path, "wb") as f:
        f.write(file_decrypted)
    # write file info to database
    data_base.add_file(user_id=client_req.client_id, file_name=file_name, path=path)
    # calculate and return cksum
    sha256_hash = hashlib.sha256()
    with open(path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
        return sha256_hash.digest()
