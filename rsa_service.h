/**
 * 
 * @author:       kylin
 * @email:        kylin.du@outlook.com
 * @dateTime:     2018-06-06 Wed 15:34:58
 * @copyright:    kylin
 * @description:  
 * 
 */

#ifndef _RSA_SERVICE_H_
#define _RSA_SERVICE_H_

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

#include "base.h"

namespace NetCore {

class RSAService {
public:
    enum {DEFAULT_ENCRYPT_BIT_LEN = 2144,PADDING_OFF = 12};//can not change
public:
    RSAService(char*& token) {
        _priv = NULL;
        _pub = NULL;
        _elen = 0;
        _token = (char*)nc_malloc(strlen(token) + 1);
        strcpy(_token,token);
    }
    RSAService(char*&& token) {
        _priv = NULL;
        _pub = NULL;
        _elen = 0;
        _token = (char*)nc_malloc(strlen(token) + 1);
        strcpy(_token,token);
    }
    RSAService(const char*& token) {
        _priv = NULL;
        _pub = NULL;
        _elen = 0;
        _token = (char*)nc_malloc(strlen(token) + 1);
        strcpy(_token,token);
    }
    RSAService(const char*&& token) {
        _priv = NULL;
        _pub = NULL;
        _elen = 0;
        _token = (char*)nc_malloc(strlen(token) + 1);
        strcpy(_token,token);
    }
    ~RSAService() {
        if (_priv) {
            RSA_free(_priv);
        }

        if (_pub) {
            RSA_free(_pub);
        }

        SAFE_FREE(_token);
    }
public:
    inline bool init(unsigned int elen = DEFAULT_ENCRYPT_BIT_LEN) {//only useful in the fst time!
        _elen = elen;
        _priv = rsa_fetch_private_key("priv.key");
        if (!_priv) {
            if (rsa_generate_key_files("pub.key", "priv.key") != 0) {
                printf("RSAService >> generate key files err!\n");
                return false;
            }
            printf("RSAService >> generate new key files\n");
            _priv = rsa_fetch_private_key("priv.key");
            if (!_priv) {
                printf("RSAService >> fetch private key failed\n");
                return false;
            }
        }

        _pub = rsa_fetch_public_key("pub.key");
        if (!_pub) {
            printf("RSAService >> fetch public key failed\n");
            return false;
        }

        _elen = RSA_size(_priv);
        assert(RSA_size(_pub) == _elen);

        printf("RSAService is ready!\n");
        return true;
    }
    //encrypt & decrypt
    inline bool rsa_pub_key_encrypt(const unsigned char* from, size_t flen, data_t& to) {
        if (flen == 0 || from == 0) {
            return false;
        }
        //int rsa_len = RSA_size(_priv);
        unsigned int eplen = max_encrypt_size();
        unsigned int sval = (flen + eplen - 1)/eplen;
        unsigned int ulen = sval * _elen;
        unsigned int ne = 0;
        unsigned int nleft = flen;
        to._data = (uint8_t*)nc_malloc(ulen);
        if (UNLIKELY(!to._data)) {
            return false;
        }
        to._capacity = ulen;
        to._size = 0;
        int tlen = 0;

        do {
            ne = nleft > eplen ? eplen : nleft;
            if (UNLIKELY((tlen = RSA_public_encrypt(ne, from + (flen - nleft), to._data + to._size, _pub, RSA_PKCS1_PADDING)) <= 0)) {
                return false;
            }
            to._size += (uint32_t)tlen;
            nleft -= ne;
        }while(nleft > 0);

        return true;
    }
    inline bool rsa_pub_key_decrypt(const unsigned char* from, size_t flen, data_t& to) {
        if (flen == 0 || from == 0) {
            return false;
        }
        //int rsa_len = RSA_size(_pub);
        unsigned int sval = (flen + _elen - 1)/_elen;
        unsigned int ulen = sval * max_encrypt_size();
        unsigned int ne = 0;
        unsigned int nleft = flen;
        to._data = (uint8_t*)nc_malloc(ulen);
        if (UNLIKELY(!to._data)) {
            return false;
        }
        to._capacity = ulen;
        to._size = 0;
        int tlen = 0;

        do {
            ne = nleft > _elen ? _elen : nleft;
            if (UNLIKELY((tlen = RSA_public_decrypt(ne, from + (flen - nleft), to._data + to._size, _pub, RSA_PKCS1_PADDING)) <= 0)) {
                return false;
            }
            to._size += (uint32_t)tlen;
            nleft -= ne;
        }while(nleft > 0);

        return true;
    }
    inline bool rsa_priv_key_encrypt(const unsigned char* from, size_t flen, data_t& to) {
        if (flen == 0 || from == 0) {
            return false;
        }
        //int rsa_len = RSA_size(_priv);
        unsigned int eplen = max_encrypt_size();
        unsigned int sval = (flen + eplen - 1)/eplen;
        unsigned int ulen = sval * _elen;
        unsigned int ne = 0;
        unsigned int nleft = flen;
        to._data = (uint8_t*)nc_malloc(ulen);
        if (UNLIKELY(!to._data)) {
            return false;
        }
        to._capacity = ulen;
        to._size = 0;
        int tlen = 0;

        do {
            ne = nleft > eplen ? eplen : nleft;
            if (UNLIKELY((tlen = RSA_private_encrypt(ne, from + (flen - nleft), to._data + to._size, _priv, RSA_PKCS1_PADDING)) <= 0)) {
                return false;
            }
            to._size += (uint32_t)tlen;
            nleft -= ne;
        }while(nleft > 0);

        return true;
    }
    inline bool rsa_priv_key_decrypt(const unsigned char* from, size_t flen, data_t& to) {
        if (flen == 0 || from == 0) {
            return false;
        }
        //int rsa_len = RSA_size(_pub);
        unsigned int sval = (flen + _elen - 1)/_elen;
        unsigned int ulen = sval * max_encrypt_size();
        unsigned int ne = 0;
        unsigned int nleft = flen;
        to._data = (uint8_t*)nc_malloc(ulen);
        if (UNLIKELY(!to._data)) {
            return false;
        }
        to._capacity = ulen;
        to._size = 0;
        int tlen = 0;

        do {
            ne = nleft > _elen ? _elen : nleft;
            if (UNLIKELY((tlen = RSA_private_decrypt(ne, from + (flen - nleft), to._data + to._size, _priv, RSA_PKCS1_PADDING)) <= 0)) {
                return false;
            }
            to._size += (uint32_t)tlen;
            nleft -= ne;
        }while(nleft > 0);

        return true;
    }
    inline unsigned int max_encrypt_size() {return _elen - PADDING_OFF;}
    inline unsigned int max_encrypt_result_size() {return _elen;}
private:
    /*generate keys*/
    inline int rsa_generate_key_files(const char* pub_key_file, const char* priv_key_file) {
        if (_elen <= PADDING_OFF) {
            return -1;
        }
        RSA *rsa = NULL;
        //string to make the random number generator initialized
        const char rnd_seed[] = "asfnkhwhw8af8271*J89*a$hskawj#ndajh11;a;mq1.SFKSAawk'*8885awbewa63/9);N";
        RAND_seed(rnd_seed, sizeof(rnd_seed));
        rsa = RSA_generate_key(_elen, RSA_F4, 0, 0);
        if (rsa == NULL) {
            printf("RSA_generate_key error!\n");
            return -1;
        }

        //生成公钥文件
        BIO *bio_pub = BIO_new(BIO_s_file());
        if (NULL == bio_pub) {
            printf("generate_key bio file new error!\n");
            return -1;
        }
        if (BIO_write_filename(bio_pub, (void *)pub_key_file) <= 0) {
            printf("BIO_write_filename for pub error!\n");
            return -1;
        }

        if (PEM_write_bio_RSAPublicKey(bio_pub, rsa) != 1) {
            printf("PEM_write_bio_RSAPublicKey error!\n");
            return -1;
        }
        printf("Create public key ok!\n");
        BIO_free_all(bio_pub);

        // 生成私钥文件
        BIO *bio_priv = BIO_new_file(priv_key_file, "w+");
        if (NULL == bio_priv) {
            printf("generate_key bio file new error2!\n");
            return -1;
        }

        if (PEM_write_bio_RSAPrivateKey(bio_priv, rsa, NULL, NULL, 0, NULL, _token) != 1) {
            printf("PEM_write_bio_RSAPrivateKey error!\n");
            return -1;
        }

        printf("Create private key ok!\n");
        BIO_free_all(bio_priv);
        RSA_free(rsa);
        return 0;
    }
    /*fetch private key*/
    inline RSA* rsa_fetch_private_key(const char* priv_key_file) {
        RSA *rsa = RSA_new();
        OpenSSL_add_all_algorithms();
        BIO *bio_priv = NULL;
        bio_priv = BIO_new_file(priv_key_file, "rb");
        if (NULL == bio_priv) {
            printf("open_private_key bio file new error!\n");
            return NULL;
        }

        rsa = PEM_read_bio_RSAPrivateKey(bio_priv, &rsa, NULL, _token);
        BIO_free(bio_priv);
        return rsa;
    }
    /*fetch public key*/
    inline RSA* rsa_fetch_public_key(const char* pub_key_file) {
        RSA *rsa = NULL;

        OpenSSL_add_all_algorithms();
        BIO *bio_pub = BIO_new(BIO_s_file());
        BIO_read_filename(bio_pub, pub_key_file);
        if (NULL == bio_pub) {
            printf("open_public_key bio file new error!\n");
            return NULL;
        }

        rsa = PEM_read_bio_RSAPublicKey(bio_pub, NULL, NULL, NULL);
        BIO_free(bio_pub);
        return rsa;
    }

private:
    RSA* _priv;
    RSA* _pub;
    unsigned int _elen;
    char* _token;
};


};

#endif //_RSA_SERVICE_H_