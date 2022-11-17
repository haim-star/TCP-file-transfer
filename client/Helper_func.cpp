#include "Helper_func.h"

// create and return private key
RSA::PrivateKey create_private_key(AutoSeededRandomPool* rng) {
    // Create Keys
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(*rng, 1024); 
    return privateKey;
}

// get private key, create and return the public key
RSA::PublicKey create_public_key(RSA::PrivateKey p_key) {
    RSA::PublicKey publicKey(p_key);
    return publicKey;
}

// return the string format of private key
string get_private_key(RSA::PrivateKey p_key) {
    string private_key;
    Base64Encoder privKeySink(new StringSink(private_key));
    p_key.DEREncode(privKeySink);
    privKeySink.MessageEnd();
    return private_key;
}

// return the string format of public key
string get_public_key(RSA::PublicKey p_key) {
    string public_key;
    Base64Encoder pubKeySink(new StringSink(public_key));
    p_key.DEREncode(pubKeySink);
    pubKeySink.MessageEnd();
    return public_key;
}

// get file stream reader, return the n line in the file
string get_the_n_line_from_file(ifstream* stream, int n) {
    stream->clear();
    stream->seekg(0, ios::beg);
    string line;
    while (n >= 1) {
        getline(*stream, line);
        n--;
    }
    return line;
}

// return file size of file in given path
// return 0 if error
int get_file_size(std::string filename) 
{
    FILE* p_file = NULL;
    fopen_s(&p_file, filename.c_str(), "rb");
    if (!p_file)
        return 0;
    fseek(p_file, 0, SEEK_END);
    int size = ftell(p_file);
    fclose(p_file);
    return size;
}

// write string(append) to "me.info" file
// return 0 if error
int write_to_me_file(string s) {
    ofstream WriteMeFile("me.info", ios::app);
    if (!WriteMeFile)
        return 0;
    WriteMeFile << s << endl;
    WriteMeFile.close();
    return 1;
}

// write public key to file: "me.info"
// return 0 if error
int write_public_key(ifstream* read, string public_key_str) {
    string name = get_the_n_line_from_file(read, 1);
    string id = get_the_n_line_from_file(read, 2);
    read->close();
    ofstream write("me.info");
    if (!write)
        return 0;
    write << name << endl << id << endl << public_key_str;
    write.close();
    read->open("me.info");
    if (!read)
        return 0;
    return 1;
}

// compare two char array
bool compare(char* a, char* b, int len) {
    for (int i = 0; i < len; i++) {
        if (*a != *b)
            return false;
    }
    return true;
}

// clear char array memory
void clear(char message[], int length) {
    for (int i = 0; i < length; i++)
        message[i] = '\0';
}
