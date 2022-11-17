import parser
from request_payloads import NamePayload, KeyPayload, FilePayload, CRCPayload
from consts import Sizes, RequestCode


#  Request parsing obj
class Request:

    def __init__(self, bytes_request: bytearray):
        request_index = 0
        # set client id from byte data
        self.client_id = parser.get_str_from_bytes(byte_arr=bytes_request, from_ind=request_index,
                                                   size=Sizes.CLIENT_ID_SIZE)
        request_index += Sizes.CLIENT_ID_SIZE
        # set version from byte data
        self.version = parser.get_int_from_bytes(byte_arr=bytes_request, from_ind=request_index,
                                                 size=Sizes.VERSION_SIZE)
        request_index += Sizes.VERSION_SIZE
        # set request code from byte data
        self.code = parser.get_int_from_bytes(byte_arr=bytes_request, from_ind=request_index,
                                              size=Sizes.CODE_SIZE)
        request_index += Sizes.CODE_SIZE
        # set payload len from byte data
        self.payload_len = parser.get_int_from_bytes(byte_arr=bytes_request, from_ind=request_index,
                                                     size=Sizes.PAYLOAD_LEN_SIZE)
        request_index += Sizes.PAYLOAD_LEN_SIZE
        bytes_payload = parser.get_sub_byte_arr(byte_arr=bytes_request, from_ind=request_index,
                                                size=self.payload_len)
        # set payload obj from byte data
        match self.code:
            case RequestCode.REGISTRATION:
                self.payload = NamePayload(bytes_payload=bytes_payload)
            case RequestCode.SEND_PUBLIC_KEY:
                self.payload = KeyPayload(bytes_payload=bytes_payload)
            case RequestCode.SEND_FILE:
                self.payload = FilePayload(bytes_payload=bytes_payload)
            case RequestCode.CRC_OK | RequestCode.CRC_SECOND | RequestCode.CRC_ERROR:
                self.payload = CRCPayload(bytes_payload=bytes_payload)
            case _:
                raise Exception("Invalid Request code. (The request content is incorrect)")
