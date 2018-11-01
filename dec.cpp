#include <iostream>
#include "cryptoCPP.h"
#include <string>

int main( int argc, char* argv[])
{
    std::string key,message;


    crypto_DES des;


    message = argv[1];

    key = argv[2];


    
    std::string dec = des.decrypt(message, ASCII_1, key, HEX_0, ECB_0);

    std::cout<<dec;

}
