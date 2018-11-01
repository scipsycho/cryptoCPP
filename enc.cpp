#include <iostream>
#include "cryptoCPP.h"
#include <string>

int main( int argc, char *argv[])
{
    std::string key,message;

    message = argv[1];

    key = argv[2];

    crypto_DES des;

    std::string enc = des.encrypt(message, ASCII_1, key, HEX_0, ECB_0);

    std::cout<<enc;




}
