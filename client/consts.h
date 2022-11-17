#pragma once

const int REGISTRATION = 1100;
const int SEND_PUBLIC_KEY = 1101;
const int SEND_FILE = 1103;
const int CRC_OK = 1104;
const int CRC_SECOND = 1005;
const int CRC_ERROR = 1006;



const int REGISTRATION_OK = 2100;
const int REGISTRATION_FAIL = 2101;
const int RECEIVE_PUBLIC_KEY = 2102;
const int RECEIVE_FILE = 2103;
const int RECEIVE_MES = 2104;

const int CLIENT_ID_SIZE = 16;
const int CODE_SIZE = 2;
const int VERSION_SIZE = 1;
const int PAYLOAD_LEN_SIZE = 4;
const int CONTENT_SIZE = 4;
const int NAME_SIZE = 255;
const int FILE_NAME_SIZE = 255;
const int PUBLIC_KEY_SIZE = 218;
const int CRC_SIZE = 32;

const int VERSION = 3;

const int max_length = 1024;
const int default_port = 1234;
const int AES_KEY_SIZE = 16;
const int CKSUM_SIZE = 32;
