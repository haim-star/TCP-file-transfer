#include "Helper_func.h"

int main()
{
    try {
        boost::asio::io_service io_service;
        boost::system::error_code error;
        //socket creation
        tcp::socket socket(io_service);
        //connection
        socket.connect(tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), default_port), error);
        if (error)
            throw runtime_error("[-] Error: open socket fail!");
        cout << "[+] Start Client..." << endl;

        ifstream ReadMeFile;
        ReadMeFile.open("me.info");
        // =========== if file "me.info" not exist - Registration ===========
        if (!ReadMeFile) {
            cout << "[!] file: me.info not exist!" << endl;
            // read name from "transfer.me" file
            ifstream ReadTransferFile;
            ReadTransferFile.open("transfer.info");
            if (!ReadTransferFile)
                throw runtime_error("[-] Error: open file to read/write fail!");
            string name = get_the_n_line_from_file(&ReadTransferFile, 2);
            ReadTransferFile.close();

            // write mane to "me.info" file
            int ret_val = write_to_me_file(name);
            if (ret_val == 0)
                throw runtime_error("[-] Error: open file to read/write fail!");

            // create Registration payload and send to server
            char payload[NAME_SIZE];
            clear(payload, NAME_SIZE);
            memcpy(payload, name.c_str(), name.size());
            Request* req = new Registration(payload);
            boost::asio::write(socket, boost::asio::buffer(req->getRequestData(), max_length), error);
            boost::asio::write(socket, boost::asio::buffer("", max_length)); // EOF
            delete req;
            if (error)
                throw runtime_error("[-] Error: send connection message failed!");
            cout << "[+] Registration message sent successfully!" << endl;

            // get Response from server - write userId to "me.info" file
            char reply[max_length];
            size_t reply_length = boost::asio::read(socket, boost::asio::buffer(reply, max_length));
            Response* res = new Response(reply);
            // if registration fail - end run
            if (res->get_code() == REGISTRATION_FAIL) {
                cout << "[!] Registration failed!";
                // remove file "me.info"
                if (remove("me.info") != 0)
                    throw runtime_error("[-]Error deleting file");
                return 0;
            }
            write_to_me_file(res->get_payload());
        }

        // =========== if file "me.info" exist - start from here ===========
        if (!ReadMeFile)
            ReadMeFile.open("me.info");

        // generate private and public keys, and write them to "me.info" file
        AutoSeededRandomPool rng;
        RSA::PrivateKey private_key = create_private_key(&rng);
        RSA::PublicKey public_key = create_public_key(private_key);
        string public_key_str = get_public_key(public_key);
        write_public_key(&ReadMeFile, public_key_str);

        // create payload for sending public key to server, and send
        char pub_key_payload[NAME_SIZE + PUBLIC_KEY_SIZE];
        clear(pub_key_payload, NAME_SIZE + PUBLIC_KEY_SIZE);
        string name = get_the_n_line_from_file(&ReadMeFile, 1);
        memcpy(pub_key_payload, name.c_str(), name.size());
        memcpy(pub_key_payload + NAME_SIZE, public_key_str.c_str(), PUBLIC_KEY_SIZE);
        char cid[CLIENT_ID_SIZE];
        memcpy(cid, get_the_n_line_from_file(&ReadMeFile, 2).c_str(), CLIENT_ID_SIZE);
        Request* pub_key_request = new PublicKeyReq(cid, pub_key_payload);
        boost::asio::write(socket, boost::asio::buffer(pub_key_request->getRequestData(), max_length), error);
        boost::asio::write(socket, boost::asio::buffer("", max_length)); // EOF
        delete pub_key_request;
        if (error)
            throw runtime_error("[-] Error: send public key failed!");
        ReadMeFile.close();
        cout << "[+] public key sent successfully!" << endl;

        // get Response from server - get the AES encrypted key
        char reply[max_length];
        size_t reply_length = boost::asio::read(socket, boost::asio::buffer(reply, max_length));
        Response* res = new Response(reply);
        int aes_len = res->get_payload_len() - CLIENT_ID_SIZE;
        char* aes_encrypted = new char[aes_len];
        memcpy(aes_encrypted, res->get_payload() + CLIENT_ID_SIZE, aes_len);

        // decrypte the AES key with the private key
        std::string decrypted;
        RSAES_OAEP_SHA_Decryptor d(private_key);
        StringSource ss_cipher(reinterpret_cast<const byte*>(aes_encrypted), 128, true, new PK_DecryptorFilter(rng, d, new StringSink(decrypted)));
        delete[] aes_encrypted;

        // read file name from "tranfer.info" file
        ifstream ReadTransferFile("transfer.info");
        if (!ReadTransferFile)
            throw runtime_error("[-] Error: open file to read/write fail!");
        string file_name = get_the_n_line_from_file(&ReadTransferFile, 3);
        ReadTransferFile.close();

        // read the file
        int f_size = get_file_size(file_name);
        char* file = new char[f_size];
        ifstream file_read(file_name, std::ios_base::binary);
        if (!file_read)
            throw runtime_error("[-] Error: open file to read/write fail!");
        file_read.read(file, f_size);
        file_read.close();

        // file encryption - with the AES key
        byte aes_key[AES_KEY_SIZE];
        std::memcpy(aes_key, decrypted.c_str(), AES_KEY_SIZE);
        CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };
        CryptoPP::AES::Encryption aesEncryption(reinterpret_cast<const byte*>(aes_key), AES_KEY_SIZE);
        CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
        string cipher;
        CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipher));
        stfEncryptor.Put(reinterpret_cast<const CryptoPP::byte*>(file), f_size);
        stfEncryptor.MessageEnd();

        // calculate the cksum of the file
        byte check_sum[CryptoPP::SHA256::DIGESTSIZE];
        CryptoPP::SHA256().CalculateDigest(check_sum, reinterpret_cast<const CryptoPP::byte*>(file), f_size);
        delete[] file;

        // create the send file payload
        size_t cipher_len = cipher.length();
        char* file_encrypt = new char[cipher_len];
        memcpy(file_encrypt, cipher.c_str(), cipher_len);
        int payload_size = CLIENT_ID_SIZE + 4 + 255 + f_size;
        char* send_file_payload = new char[payload_size];
        clear(send_file_payload, payload_size);
        memcpy(send_file_payload, cid, CLIENT_ID_SIZE);
        memcpy(send_file_payload + CLIENT_ID_SIZE, &cipher_len, CONTENT_SIZE);
        memcpy(send_file_payload + CLIENT_ID_SIZE + CONTENT_SIZE, file_name.c_str(), file_name.size());
        memcpy(send_file_payload + CLIENT_ID_SIZE + CONTENT_SIZE + FILE_NAME_SIZE, file_encrypt, cipher_len);
        Request* send_file_request = new SendFileReq(cid, send_file_payload, cipher_len);

        // Count the number of transmissions of the file - in case of failure
        bool need_to_send_file = true;
        int send_count = 0;
        while (need_to_send_file) {
            // send  encrypted file to server
            for (int i = 0; i < send_file_request->get_data_len(); i += 1024)
                boost::asio::write(socket, boost::asio::buffer(send_file_request->getRequestData() + i, max_length), error);
            boost::asio::write(socket, boost::asio::buffer("", 1024));  //  EOF
            if (error)
                throw runtime_error("[-] Error: send file failed!");
            cout << "[+] file sent successfully!" << endl;

            // get Response from server - save the servers cksum
            reply_length = boost::asio::read(socket, boost::asio::buffer(reply, max_length));
            res = new Response(reply);
            char check_sum_server[CKSUM_SIZE];
            memcpy(check_sum_server, res->get_payload() + CLIENT_ID_SIZE + CONTENT_SIZE + FILE_NAME_SIZE, CKSUM_SIZE);

            // create the CRC payload
            char crc_payload[CLIENT_ID_SIZE + FILE_NAME_SIZE];
            clear(crc_payload, CLIENT_ID_SIZE + FILE_NAME_SIZE);
            memcpy(crc_payload, cid, CLIENT_ID_SIZE);
            memcpy(crc_payload + CLIENT_ID_SIZE, file_name.c_str(), file_name.size());

            // compare cksum with servers cksum
            if (compare((char*)check_sum, check_sum_server, CKSUM_SIZE)) {
                // ========== CRC OK - The file was sent successfully ==========
                // send Requerst to server - CRC OK, can close the socket
                Request* crc_ok = new CrcOk(cid, crc_payload);
                boost::asio::write(socket, boost::asio::buffer(crc_ok->getRequestData(), max_length), error);
                boost::asio::write(socket, boost::asio::buffer("", 1024)); // EOF
                if (error)
                    throw runtime_error("[-] Error: send CRC Confirmation message failed!");
                cout << "[+] CRC Confirmation message sent successfully!" << endl;

                // get response from server (The termination message was received by the server)
                reply_length = boost::asio::read(socket, boost::asio::buffer(reply, max_length));
                need_to_send_file = false;
                res = new Response(reply);
                if (res->get_code() == RECEIVE_MES) {
                    // close the socket
                    socket.close();
                    cout << "[!] socket closed!";
                }
            }
            else {
                // ========== CRC Fail ===========
                send_count++;
                if (send_count < 4) {   // send Resuest to server - Send file agein!
                    Request* crc_send_agein = new CrcSendAgein(cid, crc_payload);
                    boost::asio::write(socket, boost::asio::buffer(crc_send_agein->getRequestData(), max_length), error);
                    boost::asio::write(socket, boost::asio::buffer("", 1024)); // EOF
                }
                else {                  // send Request to server - The send failed!
                    Request* crc_fail = new CrcFail(cid, crc_payload);
                    boost::asio::write(socket, boost::asio::buffer(crc_fail->getRequestData(), max_length), error);
                    boost::asio::write(socket, boost::asio::buffer("", 1024)); // EOF

                    // get response from server (The termination message was received by the server)
                    reply_length = boost::asio::read(socket, boost::asio::buffer(reply, max_length));
                    res = new Response(reply);
                    if (res->get_code() == RECEIVE_MES) {
                        // close the socket
                        socket.close();
                        cout << "[!] socket closed!";
                    }
                }
            }
        }
           
        delete send_file_request;
        delete[] file_encrypt;
        delete res;
        return 0;
    }
    catch (const runtime_error& error){
        cout << error.what() << endl;
        cout << "[!] Stop Running !!!";
        return 0;
    } 
}