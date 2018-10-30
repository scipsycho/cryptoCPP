#include <iostream>
#include "cryptoCPP.h"
#include <string>

int main()
{
    std::string key,message;

    std::cout<<"Enter the message in ASCII (without spaces): ";
    std::cin>>message;

    std::cout<<"Enter the key (in hex. must be 16 chars long): ";
    std::cin>>key;

    crypto_DES des;

    std::string enc = des.encrypt(message, ASCII_1, key, HEX_0, ECB_0);

    std::cout<<"Encrypted message is : "<<enc<<std::endl;


    std::cout<<"Enter the message you want to decrypt (in hex. must be a multiple of 16 chars): ";
    std::cin>>message;


    std::cout<<"Enter the key (in hex. must be 16 chars long): ";
    std::cin>>key;
    
    std::string dec = des.decrypt(message, ASCII_1, key, HEX_0, ECB_0);

    std::cout<<"Decrypted message is : "<<dec<<std::endl;

}
