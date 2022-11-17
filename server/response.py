import consts
import parser
from consts import Sizes, ResponseCode


# response for client
class Response:

    def __init__(self, code: int):
        self.version = consts.VERSION
        self.code = code
        self.payload = None
        self.payload_size = 0

    # copy response object variables to Response bytes data
    def build_response(self):
        # set response length
        res_bytes = bytearray(Sizes.CODE_SIZE + Sizes.VERSION_SIZE + Sizes.PAYLOAD_LEN_SIZE + self.payload_size)
        ind = 0
        # copy version
        parser.copy_int_to_bytearray(byte_arr=res_bytes, int_to_copy=self.version, from_ind=ind,
                                     len_bytes=Sizes.VERSION_SIZE)
        ind += Sizes.VERSION_SIZE
        # copy code
        parser.copy_int_to_bytearray(byte_arr=res_bytes, int_to_copy=self.code, from_ind=ind,
                                     len_bytes=Sizes.CODE_SIZE)
        ind += Sizes.CODE_SIZE
        # copy payload size
        parser.copy_int_to_bytearray(byte_arr=res_bytes, int_to_copy=self.payload_size, from_ind=ind,
                                     len_bytes=Sizes.PAYLOAD_LEN_SIZE)
        ind += Sizes.PAYLOAD_LEN_SIZE
        # copy payload
        if self.payload:
            parser.copy_byte_arr_to_byte_arr(from_byte_arr=self.payload, to_byte_arr=res_bytes, to_ind=ind)
        return res_bytes


# Registration Success Response
class ResponseRegistrationSucceeded(Response):

    def __init__(self, client_id: str):
        super().__init__(code=ResponseCode.REGISTRATION_OK)
        # build payload
        self.payload = bytearray(Sizes.CLIENT_ID_SIZE)
        self.payload_size = len(self.payload)
        # copy client id
        parser.copy_str_to_bytearray(byte_arr=self.payload, str_to_copy=client_id, from_ind=0)


# Registration Fail Response
class ResponseRegistrationFail(Response):

    def __init__(self):
        super().__init__(code=ResponseCode.REGISTRATION_FAIL)


# Send AES key Response
class ResponseReceivedPublicKeySendPrivateAES(Response):

    def __init__(self, client_id: str, key_aes: bytes):
        super().__init__(code=ResponseCode.RECEIVE_PUBLIC_KEY)
        # build payload
        self.payload = bytearray(Sizes.CLIENT_ID_SIZE + len(key_aes))
        self.payload_size = len(self.payload)
        # copy client id
        parser.copy_str_to_bytearray(byte_arr=self.payload, str_to_copy=client_id, from_ind=0)
        # copy AES key
        parser.copy_byte_arr_to_byte_arr(from_byte_arr=bytearray(key_aes), to_byte_arr=self.payload,
                                         to_ind=Sizes.CLIENT_ID_SIZE)


# CRC Response
class ResponseReceivedFile(Response):

    def __init__(self, client_id: str, content_size: int, file_name: str, crc: bytes):
        super().__init__(code=ResponseCode.RECEIVE_FILE)
        # build payload
        self.payload = bytearray(Sizes.CLIENT_ID_SIZE + Sizes.CONTENT_SIZE + Sizes.FILE_NAME_SIZE + Sizes.CRC_SIZE)
        self.payload_size = len(self.payload)
        ind = 0
        # copy client id
        parser.copy_str_to_bytearray(byte_arr=self.payload, str_to_copy=client_id, from_ind=ind)
        ind += Sizes.CLIENT_ID_SIZE
        parser.copy_int_to_bytearray(byte_arr=self.payload, int_to_copy=content_size, from_ind=ind,
                                     len_bytes=Sizes.CONTENT_SIZE)
        ind += Sizes.CONTENT_SIZE
        # copy file name
        parser.copy_str_to_bytearray(byte_arr=self.payload, str_to_copy=file_name, from_ind=ind)
        ind += Sizes.FILE_NAME_SIZE
        # copy CRC
        parser.copy_byte_arr_to_byte_arr(from_byte_arr=bytearray(crc), to_byte_arr=self.payload, to_ind=ind)


# Received message Response
class ResponseReceivedMes(Response):

    def __init__(self):
        super().__init__(code=ResponseCode.RECEIVE_MES)
