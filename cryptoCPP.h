#ifndef  _INCLUDE_CRYPTOCPP_HEADER_
#define _INCLUDE_CRYPTOCPP_HEADER_


#include <sstream>
#include <vector>
#define ll unsigned long long int
enum PAD_TYPE { NORM_0 =0, PKCS5=1 , PAD_TYPE_MAX };
enum STRING_TYPE { HEX_0 = 0, ASCII_1 , STRING_TYPE_MAX};
enum ENCRYPTION_MODE { ECB_0 = 0, CBC_1 , ENCRYPTION_MODE_MAX};
class BYTE
{
	public:
		uint8_t byte;
	
		BYTE();
		BYTE(int);
		BYTE(unsigned int t);
		BYTE(uint8_t);
		BYTE operator^(const BYTE &);
		friend BYTE operator*(const int ,const BYTE &);
		friend BYTE operator*(const BYTE &,const int );
		BYTE operator *(const BYTE &);
		BYTE operator << (std::size_t);
		BYTE operator << (int );
		BYTE operator >> (int );
		BYTE operator >> (std::size_t);
		BYTE operator & (const BYTE &);
		BYTE operator = (const BYTE &);
		operator int();
};

class crypto_AES
{
	private:
		std::string input;
		STRING_TYPE m_type;
		std::string output;
		std::vector<std::vector<BYTE> > secretKey;




		//a utility functions that performs substituition on
		//one word
		void __subBytes_transform_word__(std::vector<BYTE>&, bool = false);

		//Sub-Bytes transformation on the state
		void __subBytes_transform__(std::vector< std::vector<BYTE> >&, bool = false);

		//a utility function for XORing two words
		std::vector<BYTE> __xor_word__(std::vector<BYTE>&,
					       std::vector<BYTE>&);

		//a utility function to shift a row 
		void __shift_row_left__(std::vector<BYTE> &);	

		//a utility function to shift a row right
		void __shift_row_right__(std::vector<BYTE> &);

		//Inverse Shift Rows transformation on the state
		void __shiftRows_inv_transform__(std::vector<std::vector<BYTE> > &);
		//Shift Rows transormation on the state
		void __shiftRows_transform__(std::vector<std::vector<BYTE> >&);

		//Mix Columns transformation on the state
		void __mixColumns_transform__(std::vector<std::vector<BYTE> >&);

		//Inverse Mix Columns transformation on the state
		void __mixColumns_inv_transform__(std::vector<std::vector<BYTE> >&);
		
		//Generates keys for all rounds and returns them
		std::vector<std::vector<BYTE> > __roundKeyGen__(std::vector<BYTE>&);


		//Add Round Key transformation on the state	
		void __addRoundKey_transform__(std::vector< std::vector<BYTE> >&,
					     std::vector< std::vector<BYTE> >&,
					     int);

		//Encrypts 4Bytes of data with the key stored in words
		std::vector<BYTE> __enc_block__(std::vector<BYTE>&,
						std::vector<std::vector<BYTE> >&);

		//Decrypts 4Bytes of data with the key stored in words
		std::vector<BYTE> __dec_block__(std::vector<BYTE>&,
						std::vector<std::vector<BYTE> >&);

		//utility function to convert a string to a vector of bytes
		std::vector<BYTE> __BYTE_transform__(std::string,
						     STRING_TYPE);

		//utility function to convert vector of bytes to hex string
		std::string __hex_transform__(std::vector<BYTE> &);
		
		//utility function to convert vector of bytes to ascii string
		std::string __ascii_transform__(std::vector<BYTE> &);
		
		//function used for padding
		void __pad_message__(PAD_TYPE pad_type);

		//function to get the next block of message
		std::vector<BYTE> __getNextBlock__();

    public:	
		
        crypto_AES();
		
        //Encrypt function
		std::string encrypt(std::string,
				    STRING_TYPE,
				    std::string,
				    STRING_TYPE,
				    ENCRYPTION_MODE,
				    std::string,
				    STRING_TYPE,
				    PAD_TYPE);

		//Decrypt Function
		std::string decrypt(std::string,
				    STRING_TYPE,
				    std::string,
				    STRING_TYPE,
				    ENCRYPTION_MODE,
				    PAD_TYPE);	
};	
		
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

#endif
