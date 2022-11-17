import parser
from consts import Sizes


# get name payload
class NamePayload:

    def __init__(self, bytes_payload: bytearray):
        # read name from byte data
        self.name = parser.get_str_from_bytes(byte_arr=bytes_payload, from_ind=0, size=Sizes.NAME_SIZE)


# get public key payload
class KeyPayload(NamePayload):

    def __init__(self, bytes_payload: bytearray):
        super().__init__(bytes_payload=bytes_payload)
        # read public key from byte data
        self.public_key = parser.get_str_from_bytes(byte_arr=bytes_payload, from_ind=Sizes.NAME_SIZE,
                                                    size=Sizes.PUBLIC_KEY_SIZE)


# get file payload
class FilePayload:

    def __init__(self, bytes_payload: bytearray):
        payload_index = 0
        # read client id from byte data
        self.client_id = parser.get_int_from_bytes(byte_arr=bytes_payload, from_ind=payload_index,
                                                   size=Sizes.CLIENT_ID_SIZE)
        payload_index += Sizes.CLIENT_ID_SIZE
        # read content size from byte data
        self.content_size = parser.get_int_from_bytes(byte_arr=bytes_payload, from_ind=payload_index,
                                                      size=Sizes.CONTENT_SIZE)
        payload_index += Sizes.CONTENT_SIZE
        # read file name from byte data
        self.file_name = parser.get_str_from_bytes(byte_arr=bytes_payload, from_ind=payload_index,
                                                   size=Sizes.FILE_NAME_SIZE)
        payload_index += Sizes.FILE_NAME_SIZE
        # read the file from byte data
        self.message_content = parser.get_sub_byte_arr(byte_arr=bytes_payload, from_ind=payload_index,
                                                       size=self.content_size)


# CRC payload
class CRCPayload:

    def __init__(self, bytes_payload: bytearray):
        payload_index = 0
        # read client id from byte data
        self.client_id = parser.get_int_from_bytes(byte_arr=bytes_payload, from_ind=payload_index,
                                                   size=Sizes.CLIENT_ID_SIZE)
        payload_index += Sizes.CLIENT_ID_SIZE
        # read file name from byte data
        self.file_name = parser.get_str_from_bytes(byte_arr=bytes_payload, from_ind=payload_index,
                                                   size=Sizes.FILE_NAME_SIZE)
