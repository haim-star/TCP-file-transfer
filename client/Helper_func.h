# pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <bitset>
#include <boost/asio.hpp>
#include <boost/crc.hpp>
#include "crypto/rsa.h"
#include "crypto/osrng.h"
#include "crypto/base64.h"
#include "crypto/files.h"
#include <crypto/modes.h>
#include <crypto/aes.h>
#include <crypto/filters.h>
#include <stdexcept>
#include <immintrin.h>
#include "Request.h"
#include "Response.h"

using namespace std;
using namespace boost::asio;
using namespace CryptoPP;
using ip::tcp;

RSA::PrivateKey create_private_key(AutoSeededRandomPool* rng);

RSA::PublicKey create_public_key(RSA::PrivateKey p_key);

string get_private_key(RSA::PrivateKey p_key);

string get_public_key(RSA::PublicKey p_key);

string get_the_n_line_from_file(ifstream* stream, int n);

int get_file_size(std::string filename);

int write_public_key(ifstream* read, string public_key_str);

int write_to_me_file(string s);

bool compare(char* a, char* b, int len);

void clear(char message[], int length);

