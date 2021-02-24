#include <iostream>

#include <windows.h>
#include <wincrypt.h>
#include <winsock.h>

#pragma comment(lib, "ws2_32.lib")

// The CSP used for all non-signing operations
static HCRYPTPROV base_prov;

#define BLOBLEN 1000

//
//int encrypt_block(int keytype, const unsigned char *IV,
//                  const unsigned char *key,
//                  const unsigned char *src, unsigned int srclen,
//                  unsigned char *dest, unsigned int *destlen) {
//    // TODO: right now we reimport the key each time.  Test to see if this is quick enough or if we need to cache an imported key.
//    HCRYPTKEY hckey;
//    char keyblob[BLOBLEN];
//    BLOBHEADER *bheader;
//    DWORD *keysize;
//    BYTE *keydata;
//    int bloblen, keylen, ivlen, rval;
//    ALG_ID alg;
//    DWORD mode, _destlen;
//
//
//    bheader = (BLOBHEADER *) keyblob;
//    keysize = (DWORD *) (keyblob + sizeof(BLOBHEADER));
//    keydata = (BYTE *) ((char *) keysize + sizeof(DWORD));
//
//    memset(keyblob, 0, sizeof(keyblob));
//    bheader->bType = PLAINTEXTKEYBLOB;
//    bheader->bVersion = CUR_BLOB_VERSION;
//    bheader->aiKeyAlg = alg;
//    *keysize = keylen;
//    memcpy(keydata, key, keylen);
//    bloblen = sizeof(BLOBHEADER) + sizeof(DWORD) + keylen;
//
//    if (!CryptImportKey(base_prov, (BYTE *) keyblob, bloblen, 0, 0, &hckey)) {
//        //mserror("CryptImportKey failed");
//        return 0;
//    }
//
//    mode = CRYPT_MODE_CBC;
//    if (!CryptSetKeyParam(hckey, KP_MODE, (BYTE *) &mode, 0)) {
//        //mserror("CryptSetKeyParam failed on KP_MODE");
//        rval = 0;
//        goto end;
//    }
//    if (!CryptSetKeyParam(hckey, KP_IV, IV, 0)) {
//        //mserror("CryptSetKeyParam failed on KP_IV");
//        rval = 0;
//        goto end;
//    }
//    memcpy(dest, src, srclen);
//    _destlen = srclen;
//    if (!CryptEncrypt(hckey, 0, 1, 0, dest, &_destlen, srclen + ivlen)) {
//        //mserror("CryptEncrypt failed");
//        rval = 0;
//        goto end;
//    }
//    *destlen = _destlen;
//    rval = 1;
//
//    end:
//    if (!CryptDestroyKey(hckey)) {
//        //mserror("CryptDestroyKey failed");
//    }
//    return rval;
//}
//
//int decrypt_block(int keytype, const unsigned char *IV,
//                  const unsigned char *key,
//                  const unsigned char *src, unsigned int srclen,
//                  unsigned char *dest, unsigned int *destlen) {
//    // TODO: right now we reimport the key each time.  Test to see if this is quick enough or if we need to cache an imported key.
//    HCRYPTKEY hckey;
//    char keyblob[BLOBLEN];
//    BLOBHEADER *bheader;
//    DWORD *keysize;
//    BYTE *keydata;
//    int bloblen, keylen, ivlen, rval;
//    ALG_ID alg;
//    DWORD mode, _destlen;
//
//    bheader = (BLOBHEADER *) keyblob;
//    keysize = (DWORD *) (keyblob + sizeof(BLOBHEADER));
//    keydata = (BYTE *) ((char *) keysize + sizeof(DWORD));
//
//    memset(keyblob, 0, sizeof(keyblob));
//    bheader->bType = PLAINTEXTKEYBLOB;
//    bheader->bVersion = CUR_BLOB_VERSION;
//    bheader->aiKeyAlg = alg;
//    *keysize = keylen;
//    memcpy(keydata, key, keylen);
//    bloblen = sizeof(BLOBHEADER) + sizeof(DWORD) + keylen;
//
//    if (!CryptImportKey(base_prov, (BYTE *) keyblob, bloblen, 0, 0, &hckey)) {
//        //mserror("CryptImportKey failed");
//        return 0;
//    }
//
//    mode = CRYPT_MODE_CBC;
//    if (!CryptSetKeyParam(hckey, KP_MODE, (BYTE *) &mode, 0)) {
//        //mserror("CryptSetKeyParam failed on KP_MODE");
//        rval = 0;
//        goto end;
//    }
//    if (!CryptSetKeyParam(hckey, KP_IV, IV, 0)) {
//        //mserror("CryptSetKeyParam failed on KP_IV");
//        rval = 0;
//        goto end;
//    }
//    memcpy(dest, src, srclen);
//    _destlen = srclen;
//    if (!CryptDecrypt(hckey, 0, 1, 0, dest, &_destlen)) {
//        //mserror("CryptDecrypt failed");
//        rval = 0;
//        goto end;
//    }
//    *destlen = _destlen;
//    rval = 1;
//
//    end:
//    if (!CryptDestroyKey(hckey)) {
//        //mserror("CryptDestroyKey failed");
//    }
//    return rval;
//}

std::string getIpByHost(const std::string &hostname) {
    WSADATA ws;
    int res = ::WSAStartup(MAKEWORD(2, 2), &ws);
    if (res != 0) {
        std::cout << "Failed to initialize winsock : " << res << std::endl;
        return "";
    }
    std::string ips;
    struct hostent *host_info = gethostbyname(hostname.c_str());
    if (host_info == nullptr) {
        DWORD dw = WSAGetLastError();
        if (dw != 0) {
            if (dw == WSAHOST_NOT_FOUND) {
                std::cout << "Host is not found" << std::endl;
                return "";
            } else if (dw == WSANO_DATA) {
                std::cout << "No data record is found" << std::endl;
                return "";
            } else {
                std::cout << "Function failed with an error : " << dw << std::endl;
                return "";
            }
        }
    } else {
        std::cout << "Hostname : " << host_info->h_name << std::endl;
        int i = 0;
        while (host_info->h_addr_list[i] != nullptr) {
            struct in_addr addr = *reinterpret_cast<struct in_addr*>(host_info->h_addr_list[i++]);
            ips = inet_ntoa(addr);
            std::cout << "IP Address: " << ips << std::endl;
        }
    }
    ::WSACleanup();
    return ips;
}


int main() {
    std::cout << getIpByHost("kms.cn-hangzhou.aliyuncs.com") << std::endl;
    return 0;
}