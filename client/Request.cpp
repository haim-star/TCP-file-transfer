#include "Request.h"

// build the request obj
Request::Request(char* cid, int code, char* payload, int payload_len) {
	this->data_len = CLIENT_ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_LEN_SIZE + payload_len + 1;
	// build the bytes request
	this->data = new char[data_len];
	for (int i = 0; i < this->data_len; i++)
		this->data[i] = '\0';
	if (cid)
		memcpy(this->data, cid, CLIENT_ID_SIZE);
	int version = 3;
	memcpy(this->data + CLIENT_ID_SIZE, &version, VERSION_SIZE);
	memcpy(this->data + CLIENT_ID_SIZE + VERSION_SIZE, &code, CODE_SIZE);
	memcpy(this->data + CLIENT_ID_SIZE + VERSION_SIZE + CODE_SIZE, &payload_len, PAYLOAD_LEN_SIZE);
	memcpy(this->data + CLIENT_ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_LEN_SIZE, payload, payload_len);
}

Request::~Request() {
	delete this->data;
}

char* Request::getRequestData() {
	return data;
}

int Request::get_data_len(){
	return this->data_len;
}

Registration::Registration(char* name) : Request(NULL, REGISTRATION, name, NAME_SIZE) {}

PublicKeyReq::PublicKeyReq(char* cid, char* payload) : Request(cid, SEND_PUBLIC_KEY, payload, FILE_NAME_SIZE + PUBLIC_KEY_SIZE) {}

SendFileReq::SendFileReq(char* cid, char* payload, int size) : Request(cid, SEND_FILE, payload, CLIENT_ID_SIZE + CONTENT_SIZE + FILE_NAME_SIZE + size) {}

CrcOk::CrcOk(char* cid, char* payload) : Request(cid, CRC_OK, payload, CLIENT_ID_SIZE + FILE_NAME_SIZE) {}

CrcSendAgein::CrcSendAgein(char* cid, char* payload) : Request(cid, CRC_SECOND, payload, CLIENT_ID_SIZE + FILE_NAME_SIZE) {}

CrcFail::CrcFail(char* cid, char* payload) : Request(cid, CRC_ERROR, payload, CLIENT_ID_SIZE + FILE_NAME_SIZE) {}
