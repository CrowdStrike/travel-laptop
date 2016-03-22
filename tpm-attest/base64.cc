/* Copyright (C) 2016 by CrowdStrike, Inc., <georg@crowdstrike.com>
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the BSD license.  See the LICENSE file for details.
 */

#include <tss/tspi.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include <string>
#include <vector>
#include <iostream>
using namespace std;


int base64_decode(const string& inp, vector<BYTE>& outp) {
    BIO * bio, * b64;
    ssize_t length = (inp.size()+3)*3/4;
    outp = vector<BYTE>(length);

    bio = BIO_new_mem_buf(inp.data(), inp.size());
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    length = BIO_read(bio, outp.data(), length);
    BIO_free_all(bio);

    if(length <= 0) {
        cerr << "[-] decoding base64 value failed: " << inp << endl;
        return -1;
    }

    outp.resize(length);
    return 0;
}

int base64_encode(const vector<BYTE>& inp, string& outp) {
    BIO * bio, * b64;
    char * data;
    ssize_t length;

    bio = BIO_new(BIO_s_mem());
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, inp.data(), inp.size());
    BIO_flush(bio);
    
    length = BIO_get_mem_data(bio, &data);

    if(length <= 0) {
        cerr << "[-] encoding base64 value failed" << endl;
        return -1;
    }
   
    outp = string(data, length);
    BIO_free_all(bio);

    return 0;
}
