# rsa_service
a rsa service class imp

# environment
#apt install openssl libssl-dev

# example
```c++
#include "../rsa_service.h"

int main() {
    NetCore::RSAService rs("bad boy");
    if (rs.init() == false) {
        printf("init rsa service failed!\n");
        return 0;
    }
    unsigned char src[] = "it is a example for rsa service!happy day!!";
    printf("source: %s\n",src);
    NetCore::data_t da;
    if (rs.rsa_priv_key_encrypt(src,strlen((char*)src),da) == false) {
        printf("rsa_priv_key_encrypt err\n");
        return 0;
    }
    da._data[da._size] = 0;
    printf("encrypt: %s\n", da._data);
    NetCore::data_t dv;
    if (rs.rsa_pub_key_decrypt(da._data, da._size, dv) == false) {
        printf("rsa_pub_key_decrypt err\n");
        return 0;
    }
    dv._data[dv._size] = 0;
    printf("decrypt: %s\n",dv._data);
    return 0;
}
```

# run
 g++ test.cpp `pkg-config --cflags openssl` `pkg-config --libs openssl` -std=c++11 && ./a.out
