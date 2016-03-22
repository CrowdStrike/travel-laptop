/* Copyright (C) 2016 by CrowdStrike, Inc., <georg@crowdstrike.com>
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the BSD license.  See the LICENSE file for details.
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <string>
#include <string.h>
#include <vector>
#include <algorithm>
using namespace std;

#include <tss/tspi.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <json/json.h>


int base64_decode(const string& inp, vector<BYTE>& outp);
int base64_encode(const vector<BYTE>& inp, string& outp);


static int load_json_istream(vector<vector<BYTE> >& pcr_values,
        vector<BYTE>& quote, vector<BYTE>& sig,
        istream& is) {
    Json::Reader r;
    Json::Value v;
    string line, json;

    getline(is, line, '\n');
    if(line != "-----BEGIN TPM QUOTE-----") {
        return -ESRCH;
    }
    
    while(!is.eof()) {
        getline(is, line, '\n');
        if(line == "-----END TPM QUOTE-----") {
            break;
        }
        json += line + '\n';
    }

    if(!r.parse(json, v, false)) {
        cerr << "Failed to parse JSON text" << endl;
        return -1;
    }

    if(!v.isObject()) {
        cerr << "JSON root value is not an object" << endl;
        return -2;
    }
    
    if(!v.isMember("quote") || !v["quote"].isString() || \
            base64_decode(v["quote"].asString(), quote) < 0) {
        cerr << "Failed to parse quote" << endl;
        return -3;
    }

    if(!v.isMember("sig") || !v["sig"].isString() || \
            base64_decode(v["sig"].asString(), sig) < 0) {
        cerr << "Failed to parse sig" << endl;
        return -4;
    }

    if(!v.isMember("pcrs")) {
        cerr << "[-] no pcrs array present" << endl;
        return -5;
    }
    
    const Json::Value& json_pcrs = v["pcrs"];
    if(!json_pcrs.isArray()) {
        cerr << "[-] pcrs value is not an array" << endl;
        return -5;
    }

    pcr_values.reserve(json_pcrs.size());
    for(Json::ArrayIndex i = 0; i < json_pcrs.size(); ++i) {
        const Json::Value& json_pcr = json_pcrs[i];

        if(json_pcr.isNull()) {
            pcr_values.push_back(vector<BYTE>());
        }
        else if(json_pcr.isString()) {
            vector<BYTE> pcr;

            if(base64_decode(json_pcr.asString(), pcr) < 0) {
                goto invalid;
            }

            pcr_values.push_back(pcr);
        }
        else {
invalid:
            cerr << "pcrs array element #" << i << " is invalid"  << endl;
            return -5;
        }
    }

    return 0;
}

static int load_expect_json_istream(vector<BYTE>& pubkey_der,
        vector<BYTE>& composite_hash, vector<vector<BYTE> >& pcr_values,
        istream& is) {
    Json::Reader r;
    Json::Value v;

    if(!r.parse(is, v, false)) {
        cerr << "Failed to parse JSON text" << endl;
        return -1;
    }

    if(!v.isObject()) {
        cerr << "JSON root value is not an object" << endl;
        return -2;
    }
    
    if(!v.isMember("pubkey") || !v["pubkey"].isString() || \
            base64_decode(v["pubkey"].asString(), pubkey_der) < 0) {
        cerr << "Failed to parse pubkey" << endl;
        return -3;
    }
    
    if(!v.isMember("composite") || !v["composite"].isString() || \
            base64_decode(v["composite"].asString(), composite_hash) < 0) {
        cerr << "Failed to parse composite" << endl;
        return -4;
    }

    if(!v.isMember("pcrs")) {
        cerr << "[-] no pcrs array present" << endl;
        return -5;
    }
    
    const Json::Value& json_pcrs = v["pcrs"];
    if(!json_pcrs.isArray()) {
        cerr << "[-] pcrs value is not an array" << endl;
        return -5;
    }

    pcr_values.reserve(json_pcrs.size());
    for(Json::ArrayIndex i = 0; i < json_pcrs.size(); ++i) {
        const Json::Value& json_pcr = json_pcrs[i];

        if(json_pcr.isNull()) {
            pcr_values.push_back(vector<BYTE>());
        }
        else if(json_pcr.isString()) {
            vector<BYTE> pcr;

            if(base64_decode(json_pcr.asString(), pcr) < 0) {
                goto invalid;
            }

            pcr_values.push_back(pcr);
        }
        else {
invalid:
            cerr << "pcrs array element #" << i << " is invalid"  << endl;
            return -5;
        }
    }

    return 0;
}

static int dump_json_ostream(const vector<BYTE>& nonce,
        const vector<unsigned>& pcr_nums,
        ostream& os) {
    Json::Value v;
    Json::StyledStreamWriter w(" ");
    string nonce_s;

    if(base64_encode(nonce, nonce_s) < 0) {
        return -1;
    }

    v["nonce"] = nonce_s;
    Json::Value& p = v["pcrs"] = Json::Value(Json::arrayValue);

    for(unsigned i = 0; i < pcr_nums.size(); ++i) {
        p[i] = pcr_nums[i];
    }

    os << "-----BEGIN ATTESTATION REQUEST-----" << endl;
    w.write(os, v);
    os << "-----END ATTESTATION REQUEST-----" << endl;
    return 0;
}


static int setup_context(TSS_HCONTEXT * ctx) {
    if(Tspi_Context_Create(ctx) != TSS_SUCCESS) {
        return -ENOMEM;
    }

#if 0
    if(Tspi_Context_Connect(* ctx, NULL) != TSS_SUCCESS) {
        return -EINVAL;
    }
#endif

    return 0;
}

static void destroy_context(TSS_HCONTEXT ctx) {
    if(Tspi_Context_FreeMemory(ctx, NULL) != TSS_E_INVALID_HANDLE) {
        Tspi_Context_Close(ctx);
    }
}


static int verify_quote(TSS_HCONTEXT ctx, const vector<BYTE>& composite_hash,
        const vector<BYTE>& nonce, vector<BYTE>& quote,
        vector<BYTE>& sig, TSS_HKEY pubkey) {
    TSS_RESULT res;
    TSS_HHASH hash;
    size_t k;

    static const BYTE prefix[] = {
        // 1.1.0.0 'QUOT'
        0x01, 0x01, 0x00, 0x00, 0x51, 0x55, 0x4f, 0x54
    };

    if(quote.size() != sizeof(prefix) + 40 || memcmp(quote.data(), prefix,
                sizeof(prefix)) != 0) {
        cerr << "Invalid quote structure" << endl;
        return -EINVAL;
    }

    if(composite_hash.size() != 20 || memcmp(quote.data() + sizeof(prefix),
                composite_hash.data(), 20) != 0) {
        cerr << "Composite hash in quote does not match!" << endl;
        return -EINVAL;
    }

    if(nonce.size() != 20 || memcmp(quote.data() + sizeof(prefix) + 20,
                nonce.data(), 20) != 0) {
        cerr << "Nonce in quote does not match!" << endl;
        return -EINVAL;
    }
  
    if(Tspi_Context_CreateObject(ctx, TSS_OBJECT_TYPE_HASH,  TSS_HASH_SHA1,
                &hash) != TPM_SUCCESS) {
        cerr << "Failed to create SHA1 object" << endl;
        return -ENOMEM;
    }

    if(Tspi_Hash_UpdateHashValue(hash, quote.size(), quote.data())
            != TPM_SUCCESS) {
        cerr << "Failed to feed quote into SHA1 object" << endl;
        return -ENOMEM;
    }

    if((res = Tspi_Hash_VerifySignature(hash, pubkey, sig.size(), sig.data()))
            != TPM_SUCCESS) {
        cerr << "Failed to verify signature on quote: " << res << endl;
        return -EPERM;
    }

    return 0;
}

static int load_tss_public( TSS_HCONTEXT ctx, vector<BYTE>& pubkey_der,
        TSS_HKEY * pubkey) {
    unsigned blob_size = 0x1000;
    vector<BYTE> blob(blob_size);
    unsigned blob_type;

    if(Tspi_DecodeBER_TssBlob(pubkey_der.size(), pubkey_der.data(), &blob_type, 
                &blob_size, blob.data()) != TPM_SUCCESS) {
        cerr << "Failed to decode DER TSS blob for pubkey" << endl;
        return -EINVAL;
    }
    blob.resize(blob_size);

    if(Tspi_Context_CreateObject(ctx, TSS_OBJECT_TYPE_RSAKEY,
                TSS_KEY_TYPE_IDENTITY | TSS_KEY_SIZE_2048, pubkey)
            != TPM_SUCCESS) {
        cerr << "Failed to create pubkey object" << endl;
        return -ENOMEM;
    }

    if(Tspi_SetAttribData(* pubkey, TSS_TSPATTRIB_KEY_BLOB,
                TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
                blob.size(), blob.data()) != TPM_SUCCESS) {
        cerr << "Failed to load pubkey" << endl;
        return -EINVAL;
    }

    return 0;
}


int main(int argc, char * argv[]) {
    TSS_HCONTEXT ctx;
    TSS_HKEY pubkey;
    int res;

    ifstream config_file;

    vector<BYTE> nonce, quote, sig, pubkey_der, composite_hash;
    vector<unsigned> pcrs;
    vector<vector<BYTE> > pcr_values, pcr_values_expect;

    if(argc < 2) {
        cerr << "Usage: " << argv[0] << " <expectation_json> [shell]" << endl;
        return 42;
    }

    config_file.open(argv[1]);
    if(!config_file.is_open()) {
        cerr << "Failed to open " << argv[1] << endl;
        return 42;
    }

    if(load_expect_json_istream(pubkey_der, composite_hash, pcr_values_expect,
                config_file) < 0) {
        cerr << "Failed to load expectation from " << argv[1] << endl;
        return 42;
    }
    config_file.close();

    size_t pcr_index = 0;
    for(vector<vector<BYTE> >::iterator it = pcr_values_expect.begin();
            it != pcr_values_expect.end(); ++it, ++pcr_index) {
        if(!it->empty()) {
            pcrs.push_back(pcr_index);
        }
    }


    if(setup_context(&ctx) < 0) {
        cerr << "Setting up TSS context failed" << endl;
        res = 1;
        goto out;
    }
    
    if(load_tss_public(ctx, pubkey_der, &pubkey) < 0) {
        cerr << "Loading pubkeyfrom expectation JSON failed" << endl;
        res = 1;
        goto out;
    }

    nonce = vector<BYTE>(20);
    if(!RAND_bytes(nonce.data(), nonce.size())) {
        cerr << "Failed to generate " << nonce.size() << " bytes nonce" \
            << endl;
        res = 2;
        goto out;
    }

    if(dump_json_ostream(nonce, pcrs, cout) < 0) {
        cerr << "Failed to dump attestation request" << endl;
        res = 3;
        goto out;
    }

    if(load_json_istream(pcr_values, quote, sig, cin) < 0) {
        cerr << "Failed to parse input" << endl;
        res = 4;
        goto out;
    }

    for(vector<unsigned>::iterator it = pcrs.begin(); it != pcrs.end(); ++it) {
        if(* it > pcr_values.size() || pcr_values[* it].size() != 20) {
            cerr << "Requested hash for PCR# " << * it << " not present." \
                << endl;
            res = 5;
            goto out;
        }
        else if(pcr_values[* it] != pcr_values_expect[* it]) {
            cerr << "Supplied hash for PCR# " << * it << " does not match" \
                " expectation!" << endl;
            res = 5;
            goto out;
        }
    }

    if(verify_quote(ctx, composite_hash, nonce, quote, sig, pubkey) < 0) {
        cerr << "Quote verification failed!" << endl;
        res = 6;
        goto out;
    }

    res = 0;

    if(argc > 2) {
        string composite_b64;

        if(base64_encode(composite_hash, composite_b64) < 0) {
            composite_b64 = "yes";
        }

        setenv("TPM_ATTESTED", composite_b64.c_str(), 1);
        execvp(argv[2], &argv[2]);
        cerr << "Failed to execute " << argv[2] << endl;
    }

out:
    destroy_context(ctx);
    return res;
}
