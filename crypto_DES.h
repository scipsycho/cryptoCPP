#include <sstream>
#define ll unsigned long long int
enum STRING_TYPE { HEX_0 = 0, ASCII_1 , STRING_TYPE_MAX};
enum ENCRYPTION_MODE { ECB_0 = 0, CBC_1 , ENCRYPTION_MODE_MAX};
class crypto_DES
{
	private:
		std::string input;
		STRING_TYPE m_type;
		std::string output;
	        ll secretKey;	

	//round Function;
	ll __roundFunction__(ll,ll);		
 	
	//initial and final permutation
	ll __permut__(ll,bool);

	//utility function for circular left shift
	ll __cirLeftShift__(ll);	

	//utility function for circular right shift
	ll __cirRightShift__(ll);

	//function for generating key for next round
	ll __roundKeyGen_next__(ll &,int &);

	//function for generating key for previous round
	ll __roundKeyGen_prev__(ll &, int &);

	//utitility function for parity drop
	ll __parity_drop__(ll);

        //function for encrypting one block of data
	ll __enc_block__(ll,ll);

	//function for decrypting one block of data
	ll __dec_block__(ll,ll);

	//get next message block 
	ll __getNextBlock__();

	//pad the input message
	void __pad_message__();	
	
	//utitlity function for converting string to decimal
	ll __convert2Dec__(std::string, STRING_TYPE);


	public: 
	crypto_DES();

	std::string decrypt(std::string,
			    STRING_TYPE,
			    std::string,
			    STRING_TYPE,
			    ENCRYPTION_MODE);	
	std::string encrypt(std::string, 
			    STRING_TYPE, 
			    std::string,
			    STRING_TYPE,
			    ENCRYPTION_MODE, 
			    std::string iv="", 
			    STRING_TYPE iv_type = STRING_TYPE_MAX);
};
