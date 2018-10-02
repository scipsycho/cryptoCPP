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

	//utitility function for circular shift
	ll __cirShift__(ll);	

	//function for generating key for any round
	ll __roundKeyGen__(ll &,int &);


	//utitility function for parity drop
	ll __parity_drop__(ll);

        //function for encrypting one block of data
	ll __enc_block__(ll,ll);


	//get next message block 
	ll __getNextBlock__();

	//pad the input message
	void __pad_message__();	
	public:


	crypto_DES();
	
	std::string encrypt(std::string, 	 std::string , 
			    STRING_TYPE, STRING_TYPE,
			    ENCRYPTION_MODE );
};
