#pragma once

#include <string>
#include "consts.h"

using namespace std;

// Request obj to server
class Request {
private:
    char* data; //the byte data of the Request
    int data_len; // length of the request
public:
    Request(char* cid, int code, char* payload, int payload_len);
    ~Request();
    char* getRequestData();
    int get_data_len();
};

class Registration :
    public Request
{
public:
    Registration(char* payload);

};

// send public key to server request
class PublicKeyReq :
    public Request
{
public:
    PublicKeyReq(char* cid, char* payload);
};

// send file to server request
class SendFileReq :
    public Request
{
public:
    SendFileReq(char* cid, char* payload, int size);
};

// Confirmation that CRC is right request
class CrcOk :
    public Request
{
public:
    CrcOk(char* cid, char* payload);
};

// Mistake CRC, please send agein request 
class CrcSendAgein :
    public Request
{
public:
    CrcSendAgein(char* cid, char* payload);
};

// Mistake CRC 4 times Request
class CrcFail :
    public Request
{
public:
    CrcFail(char* cid, char* payload);
};