#pragma once

#include <string>
#include "consts.h"

using namespace std;

// Response from server
class Response {
private:
	int version;
	int code;
	int payload_len;
	char* payload;
public:
	Response(char* data);
	~Response();
	int get_version();
	int get_code();
	int get_payload_len();
	char* get_payload();
};

