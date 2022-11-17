#include "Response.h"

// build the Response obj from data
Response::Response(char* data) {
	memcpy(&this->version, data, VERSION_SIZE);
	memcpy(&this->code, data + VERSION_SIZE, CODE_SIZE);
	memcpy(&this->payload_len, data + VERSION_SIZE + CODE_SIZE, PAYLOAD_LEN_SIZE);
	if (this->payload_len != 0)
		this->payload = new char[this->payload_len];
		memcpy(this->payload, data + VERSION_SIZE + CODE_SIZE + PAYLOAD_LEN_SIZE, this->payload_len);
}

Response::~Response() {
	if (this->payload_len != 0)
		delete this->payload;
}

int Response::get_version() {
	return this->version;
}

int Response::get_code() {
	return this->code;
}

int Response::get_payload_len() {
	return this->payload_len;
}

char* Response::get_payload() {
	return this->payload;
}

