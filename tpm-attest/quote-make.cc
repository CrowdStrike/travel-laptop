/* Copyright (C) 2016 by CrowdStrike, Inc., <georg@crowdstrike.com>
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the BSD license.  See the LICENSE file for details.
 */

#include <alloca.h>
#include <stdio.h>
#include <errno.h>
#include <iostream>
#include <string>
#include <string.h>
#include <vector>
#include <algorithm>
using namespace std;

#include <tss/tspi.h>
#include <json/json.h>


int base64_decode(const string& inp, vector<BYTE>& outp);
int base64_encode(const vector<BYTE>& inp, string& outp);


static int load_json_istream(vector<BYTE>& uuid, vector<BYTE>& nonce,
        vector<unsigned>& pcrs, istream& is) {
    Json::Reader r;
    Json::Value v;
    string line, json;

    getline(is, line, '\n');
    if(line != "-----BEGIN ATTESTATION REQUEST-----") {
        return -ESRCH;
    }
    
    while(!is.eof()) {
        getline(is, line, '\n');
        if(line == "-----END ATTESTATION REQUEST-----") {
            break;
        }
        json += line + '\n';
    }

    if(!r.parse(json, v, false)) {
        cerr << "[-] failed to parse JSON text" << endl;
        return -1;
    }

    if(!v.isObject()) {
        cerr << "[-] JSON root value is not an object" << endl;
        return -2;
    }

    if(!v.isMember("nonce") || !v["nonce"].isString() || \
            base64_decode(v["nonce"].asString(), nonce) < 0) {
        cerr << "[-] failed to parse nonce" << endl;
        return -3;
    }

    if(!v.isMember("pcrs")) {
        cerr << "[-] no PCR array present" << endl;
        return -4;
    }
    
    const Json::Value& json_pcrs = v["pcrs"];
    if(!json_pcrs.isArray()) {
        cerr << "[-] PCR value is not an array" << endl;
        return -4;
    }

    pcrs.reserve(json_pcrs.size());
    for(Json::ArrayIndex i = 0; i < json_pcrs.size(); ++i) {
        const Json::Value& json_pcr = json_pcrs[i];

        if(!json_pcr.isUInt()) {
            cerr << "[-] PCR array element #" << i << "not an UInt"  << endl;
            return -4;
        }

        pcrs.push_back(json_pcr.asUInt());
    }

    return 0;
}

static void dump_json_ostream(const vector<BYTE>& quote,
        const vector<BYTE>& sig,
        const vector<BYTE>& uuid,
        const vector<unsigned>& pcr_nums,
        vector<vector<BYTE> >& pcr_values,
        ostream& os) {
    Json::Value v;
    Json::StyledStreamWriter w("  ");
    string quote_s, sig_s, uuid_s;

    if(base64_encode(quote, quote_s) < 0 || base64_encode(sig, sig_s) < 0 \
            || base64_encode(uuid, uuid_s) < 0) {
        return;
    }

    v["quote"] = quote_s;
    v["sig"] = sig_s;
    v["uuid"] = uuid_s;
    Json::Value& p = v["pcrs"] = Json::Value(Json::arrayValue);

    for(size_t i = 0; i < pcr_nums.size() && i < pcr_values.size(); ++i) {
        string b64;

        if(base64_encode(pcr_values[i], b64) >= 0) {
            p[pcr_nums[i]] = b64;
        }
    }

    os << "-----BEGIN TPM QUOTE-----" << endl;
    w.write(os, v);
    os << "-----END TPM QUOTE-----" << endl;
}


static int setup_context(TSS_HCONTEXT * ctx) {
    if(Tspi_Context_Create(ctx) != TSS_SUCCESS) {
        return -ENOMEM;
    }

    if(Tspi_Context_Connect(* ctx, NULL) != TSS_SUCCESS) {
        return -EINVAL;
    }

    return 0;
}

static void destroy_context(TSS_HCONTEXT ctx) {
    if(Tspi_Context_FreeMemory(ctx, NULL) != TSS_E_INVALID_HANDLE) {
        Tspi_Context_Close(ctx);
    }
}

static int load_key(TSS_HCONTEXT ctx, const TSS_UUID uuid,
        const char * keyblob_filename, TSS_HKEY * aik) {
    FILE * keyblob_file;
    static const TSS_UUID uuid_srk = TSS_UUID_SRK;
    TSS_HKEY srk;
    TSS_HPOLICY policy;
    static BYTE secret[] = TSS_WELL_KNOWN_SECRET;
    BYTE * keyblob;
    UINT32 keyblob_length;

    keyblob_file = fopen(keyblob_filename, "rb");
    if(!keyblob_file) {
        return -errno;
    }

    fseek(keyblob_file, 0, SEEK_END);
    keyblob_length = ftell(keyblob_file);
    fseek(keyblob_file, 0, SEEK_SET);
    keyblob = (BYTE *) alloca(keyblob_length);

    if(fread(keyblob, 1, keyblob_length, keyblob_file) != keyblob_length) {
        fclose(keyblob_file);
        return -errno;
    }

    fclose(keyblob_file);


    if(Tspi_Context_LoadKeyByUUID(ctx, TSS_PS_TYPE_SYSTEM,
                uuid_srk, &srk) != TSS_SUCCESS) {
        fprintf(stderr, "[-] fail to load SRK\n");
        return -ESRCH;
    }

    if(Tspi_GetPolicyObject(srk, TSS_POLICY_USAGE, &policy)
            != TSS_SUCCESS) {
        fprintf(stderr, "[-] fail to get SRK policy\n");
        return -ESRCH;
    }

    if(Tspi_Policy_SetSecret(policy, TSS_SECRET_MODE_SHA1,
                sizeof(secret), secret) != TSS_SUCCESS) {
        fprintf(stderr, "[-] fail to set well known SRK policy secret\n");
        return -EINVAL;
    }

    if(Tspi_Context_LoadKeyByBlob(ctx, srk, keyblob_length, keyblob, aik)
            != TSS_SUCCESS) {
        fprintf(stderr, "[-] fail to upload %zu keyblob bytes\n",
                keyblob_length);
        return -EINVAL;
    }

    switch(ERROR_CODE(Tspi_Context_RegisterKey(ctx, * aik, TSS_PS_TYPE_SYSTEM,
                uuid, TSS_PS_TYPE_SYSTEM, uuid_srk))) {
        case TPM_SUCCESS:
            return 0;

        case TSS_E_KEY_ALREADY_REGISTERED:
            return 0;

        default:
            fprintf(stderr, "[-] failed to register AIK to provided UUID\n");
            return -EINVAL;
    }
}

static int quote(TSS_HCONTEXT ctx, TSS_HKEY aik,
        const vector<unsigned>& pcr_nums,
        vector<vector<BYTE> >& pcr_values,
        TSS_VALIDATION * validation_data) {
    TSS_HPCRS pcrs;
    TSS_HTPM tpm;
    TSS_RESULT res;
    int tssres, k;
    
    pcr_values = vector<vector<BYTE> >(pcr_nums.size());
    
    if(Tspi_Context_CreateObject(ctx, TSS_OBJECT_TYPE_PCRS,
                TSS_PCRS_STRUCT_INFO, &pcrs) != TPM_SUCCESS) {
        fprintf(stderr, "[-] failed to create PCR selection handle\n"); 
        return -ENOMEM;
    }

    if(Tspi_Context_GetTpmObject(ctx, &tpm) != TPM_SUCCESS) {
        fprintf(stderr, "[-] failed to obtain handle to TPM\n");
        res = -ENOMEM;
        goto out;
    }

    k = 0;
    for(vector<unsigned>::const_iterator it = pcr_nums.begin();
            it != pcr_nums.end(); ++it, ++k) {
        if(Tspi_PcrComposite_SelectPcrIndex(pcrs, * it) != TPM_SUCCESS) {
            fprintf(stderr, "[-] failed to select PCR[%i]\n", * it);
            res = -EINVAL;
            goto out;
        }
    }

    if((tssres = Tspi_TPM_Quote(tpm, aik, pcrs, validation_data))
            != TPM_SUCCESS) {
        fprintf(stderr, "[-] failed to get actual quote: %x\n", tssres);
        res = -EINVAL;
    }
    else {
        res = 0;
    }

    k = 0;
    for(vector<unsigned>::const_iterator it = pcr_nums.begin();
            it != pcr_nums.end(); ++it, ++k) {
        BYTE * pcr_value;
        unsigned value_len;

        if(Tspi_PcrComposite_GetPcrValue(pcrs, * it, &value_len, &pcr_value)
                != TPM_SUCCESS) {
            fprintf(stderr, "[-] failed to read PCR[%i]\n", * it);
            res = -EINVAL;
            goto out;
        }

        pcr_values[k] = vector<BYTE>(pcr_value, pcr_value + value_len);
    }


    Tspi_Context_CloseObject(ctx, tpm);

out:
    Tspi_Context_CloseObject(ctx, pcrs);
    return res;
}


int main(int argc, char * argv[]) {
    TSS_HCONTEXT ctx;
    TSS_HKEY aik;
    int res;

    const char * aik_keyblob_filename = "aik_blob";

    TSS_VALIDATION validation_data = { 0 };
    vector<BYTE> uuid, nonce, quote, sig;
    vector<unsigned> pcrs;
    vector<vector<BYTE> > pcr_values;

    switch(argc) {
        case 3:
            aik_keyblob_filename = argv[2];
        case 2:
            if(base64_decode(argv[1], uuid) >= 0) {
                break;
            }

        default:
            cerr << "Usage: " << argv[0] << " <aik_uuid> [aik_blob]" << endl;
            cerr << "  aik_uuid: base64 encoded UUID for AIK" << endl;
            cerr << "  aik_blob: filename of AIK blob (optional)" << endl;
            return 42;
    }

    TSS_UUID aik_uuid;
    if(uuid.size() != sizeof(aik_uuid)) {
        fprintf(stderr, "[-] input specifies %zu bytes UUID, expected %zu\n",
                uuid.size(), sizeof(aik_uuid));
        res = 4;
        goto out;
    }
    memcpy(&aik_uuid, uuid.data(), uuid.size());

    if(load_json_istream(uuid, nonce, pcrs, cin) < 0) {
        fprintf(stderr, "[-] failed to parse input\n");
        res = 4;
        goto out;
    }
    sort(pcrs.begin(), pcrs.end());

    if(setup_context(&ctx) < 0) {
        fprintf(stderr, "[-] setting up TSS context failed (is tcsd up?)\n");
        res = 1;
        goto out;
    }

    if(load_key(ctx, aik_uuid, aik_keyblob_filename, &aik) < 0) {
        fprintf(stderr, "[-] failed to load AIK from %s\n",
                aik_keyblob_filename);
        res = 2;
        goto out;
    }

    validation_data.ulExternalDataLength = nonce.size();
    validation_data.rgbExternalData = nonce.data();

    if(::quote(ctx, aik, pcrs, pcr_values, &validation_data) < 0) {
        fprintf(stderr, "[-] getting actual quote failed\n");
        res = 3;
        goto out;
    }

    
    quote = vector<BYTE>(validation_data.rgbData,
            validation_data.rgbData + validation_data.ulDataLength);
    sig = vector<BYTE>(validation_data.rgbValidationData,
            validation_data.rgbValidationData + \
            validation_data.ulValidationDataLength);

    dump_json_ostream(quote, sig, uuid, pcrs, pcr_values, cout);

    res = 0;
out:
    destroy_context(ctx);
    return res;
}
