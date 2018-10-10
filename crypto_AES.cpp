#include <iostream>
#include <vector>
#include <iomanip>
#include "cryptoCPP.h"
BYTE::BYTE()
{
	byte = 0;
}	

BYTE::BYTE(int t)
{
	byte = (uint8_t)t;
}

BYTE::BYTE(unsigned int t)
{
	byte = (uint8_t)t;
}

BYTE::BYTE(uint8_t t)
{
	byte = t;
}

BYTE BYTE::operator^(const BYTE &a)
{	
	return BYTE(byte ^ (a.byte));
}

BYTE operator*(const int a, const BYTE &b)
{
	return BYTE(a) * b;
}

BYTE operator*(const BYTE &a, const int b)
{
	return a * BYTE(b);
}

BYTE BYTE::operator*(const BYTE &a)
{
	unsigned int temp1, temp2,temp;
	temp1 = byte;
	temp2 = a.byte;
	temp = 0;
	bool carry=false;
	while(temp2 > 0)
	{
		if(temp2 & 1)
			temp = temp ^ temp1;
		temp2 = temp2 >> 1;
		carry = (temp1 & (1<<7));
		temp1 = temp1 << 1;
		if(carry)
			temp1 ^= 0x1b;
	}
	return BYTE(temp);	
}


BYTE BYTE::operator << (std::size_t n)
{
	return BYTE(byte << n);
}

BYTE BYTE::operator << (int n)
{
	return BYTE(byte << n);
}

BYTE BYTE::operator >> (std::size_t n)
{
	return BYTE(byte >> n);
}

BYTE BYTE::operator >> (int n)
{
	return BYTE(byte >> n);
}

BYTE BYTE::operator & (const BYTE &a)
{
	return BYTE(byte & a.byte);
}

BYTE BYTE::operator = (const BYTE &b)
{
	byte = b.byte;
	return BYTE(byte);
}
	
BYTE::operator int()
{
	return (int)byte;
}

#include "constants_AES.h"

crypto_AES::crypto_AES()
{

}
void crypto_AES::__subBytes_transform_word__(std::vector< BYTE > &word, bool isInv)
{
	
	int in = 0;
	if(isInv)
		in = 1;
	BYTE mask = 0x0f;
	BYTE row,col;
	BYTE byte;
	for(int i=0; i< word.size(); i++)
	{
		byte = word[i];
		row = ( byte & ( mask << 4 ) ) >>4;
		col = byte & mask;
		word[i] = S_box[in][row][col];
	}
}

std::vector<BYTE> crypto_AES::__xor_word__(std::vector< BYTE > &word1, 
				           std::vector< BYTE > &word2)
{
	if ( word1.size() != word2.size() )
	{
		std::cerr<<"Size Incompatible!! Aborting!"<<std::endl;
		exit(1);
	}

	int n = word1.size();
	std::vector< BYTE > word(n,0);

	for(int i=0; i<n; i++)
		word[i] = word1[i] ^ word2[i];

	return word;
} 
void crypto_AES::__subBytes_transform__(std::vector< std::vector< BYTE > > &state, bool isInv )
{
	int n = state.size();
	int m = state[0].size();
	for(int i=0; i<n; i++)
	{
		__subBytes_transform_word__(state[i],isInv);
	}
}

void crypto_AES::__shift_row_left__(std::vector< BYTE > &row )
{
	BYTE temp;
	temp   = row[0];
	int n = row.size();
	
	for(int i=0; i<n-1;i++)
		row[i] = row[i+1];

	row[n-1] = temp;
}
void crypto_AES::__shift_row_right__(std::vector< BYTE > &row)
{
	BYTE temp;
	int n = row.size();
	temp = row[n-1];
	for(int i=n-1; i>0; i--)
		row[i] = row[i-1];

	row[0] = temp;
}
void crypto_AES::__shiftRows_transform__(std::vector< std::vector< BYTE > > &state )
{
	__shift_row_left__(state[1]);
	__shift_row_left__(state[2]);
	__shift_row_left__(state[2]);
	__shift_row_left__(state[3]);
	__shift_row_left__(state[3]);
	__shift_row_left__(state[3]);
}

void crypto_AES::__shiftRows_inv_transform__(std::vector< std::vector< BYTE > > &state)
{
	__shift_row_right__(state[1]);
	__shift_row_right__(state[2]);
	__shift_row_right__(state[2]);
	__shift_row_right__(state[3]);
	__shift_row_right__(state[3]);
	__shift_row_right__(state[3]);
}
void crypto_AES::__mixColumns_transform__(std::vector< std::vector< BYTE > > &state )
{
	std::vector< BYTE > state_col(4);
	for(int j = 0; j < state[0].size(); j++ )
	{
		state_col[0] = (2 * state[0][j]) ^ ( 3 * state[1][j] ) ^ ( 1 * state[2][j] ) ^ ( 1 * state[3][j] );
		state_col[1] = (1 * state[0][j]) ^ ( 2 * state[1][j] ) ^ ( 3 * state[2][j] ) ^ ( 1 * state[3][j] );
		state_col[2] = (1 * state[0][j]) ^ ( 1 * state[1][j] ) ^ ( 2 * state[2][j] ) ^ ( 3 * state[3][j] );
		state_col[3] = (3 * state[0][j]) ^ ( 1 * state[1][j] ) ^ ( 1 * state[2][j] ) ^ ( 2 * state[3][j] );
		
		state[0][j] = state_col[0];
		state[1][j] = state_col[1];
		state[2][j] = state_col[2];
		state[3][j] = state_col[3];
	}
}
void crypto_AES::__mixColumns_inv_transform__(std::vector< std::vector< BYTE > > &state )
{
	std::vector< BYTE > state_col(4);
	for(int j = 0; j < state[0].size(); j++ )
	{
		state_col[0] = (0x0e * state[0][j]) ^ ( 0x0b * state[1][j] ) ^ ( 0x0d * state[2][j] ) ^ ( 0x09 * state[3][j] );
		state_col[1] = (0x09 * state[0][j]) ^ ( 0x0e * state[1][j] ) ^ ( 0x0b * state[2][j] ) ^ ( 0x0d * state[3][j] );
		state_col[2] = (0x0d * state[0][j]) ^ ( 0x09 * state[1][j] ) ^ ( 0x0e * state[2][j] ) ^ ( 0x0b * state[3][j] );
		state_col[3] = (0x0b * state[0][j]) ^ ( 0x0d * state[1][j] ) ^ ( 0x09 * state[2][j] ) ^ ( 0x0e * state[3][j] );
		
		state[0][j] = state_col[0];
		state[1][j] = state_col[1];
		state[2][j] = state_col[2];
		state[3][j] = state_col[3];
	}
}
void show_word(std::vector<BYTE> &word)
{
	int temp;
	for(int j=0; j<word.size();j++){
		temp=word[j];
		std::cout<<std::setfill('0')<<std::setw(2)<<std::hex<<temp;
	}
}
std::vector< std::vector<BYTE> >  crypto_AES::__roundKeyGen__(std::vector<BYTE> &key)
{
	int i=0;
	
	int Nk = key.size() / 4;
	int Nr;
	std::vector<BYTE> temp;
	switch(Nk)
	{
		case 4: Nr = 10;
			break;
		case 6: Nr = 12;
			break;
		case 8: Nr = 14;
			break;
	}
	std::vector< std::vector<BYTE> > words_t(4*(Nr+1),std::vector<BYTE>(4,0));
	while( i < Nk )
	{
		for(int j = 0; j < 4; j++ )
			words_t[i][j] = key[4*i + j]; 	
		i++;
	}

	while( i < 4 * ( Nr + 1 ))
	{
		temp = words_t[i-1];
		if ( i % Nk == 0)
		{
			__shift_row_left__(temp);
			__subBytes_transform_word__(temp);
			temp[0] = temp[0] ^ R_con[i/Nk -1];
		}
		else if( ( Nk > 6 ) && (i % Nk == 4) ){
			__subBytes_transform_word__(temp);
		}
		words_t[i] = __xor_word__(words_t[i-Nk],temp);
		i++;
	}

	return words_t;
	
}
void crypto_AES::__addRoundKey_transform__(std::vector< std::vector< BYTE > > &state,
					   std::vector< std::vector< BYTE > > &words, 
					   int s )
{
	for(int j = 0; j< state[0].size(); j++)
	{
		for(int i=0; i < state.size(); i++)
			state[i][j] = state[i][j] ^ words[s+j][i];
	}
}
/*void show(std::vector<std::vector<BYTE> > &state,string s)
{
	int temp;
	std::cout<<s<<": ";
	for(int j=0; j<state[0].size(); j++)
	{
		for(int i=0; i<state.size(); i++)
		{
			temp = state[i][j];
			std::cout<<setfill('0')<<setw(2)<<std::hex<<temp;
		}
		
	}
	std::cout<<std::endl;
}*/
std::vector<BYTE> crypto_AES::__enc_block__(std::vector<BYTE> &input, 
				std::vector<std::vector<BYTE> > &words)
{
	std::vector<std::vector<BYTE> > state(4,std::vector<BYTE>(4,0));
	for(int i = 0; i<4; i++)
	{
		for(int j = 0; j<4; j++)
			state[i][j] = input[i+4*j];
	}

	int Nr = words.size()/4 - 1;
	__addRoundKey_transform__(state,words,0);
	int round = 1;

	while(round < Nr)
	{
		__subBytes_transform__(state);
		__shiftRows_transform__(state);
		__mixColumns_transform__(state);
		__addRoundKey_transform__(state,words,round*4);
		round++;
	}
	
	__subBytes_transform__(state);
	__shiftRows_transform__(state);
	__addRoundKey_transform__(state,words,round*4);

	std::vector<BYTE> output(input.size());

	for(int i=0; i<4; i++){
		for(int j=0; j<4; j++)
			output[i + 4*j] = state[i][j];
	}

	return output;	
	
}
std::vector<BYTE> crypto_AES::__dec_block__(std::vector<BYTE> &input, 
				std::vector<std::vector<BYTE> > &words)
{
	std::vector<std::vector<BYTE> > state(4,std::vector<BYTE>(4,0));
	for(int i = 0; i<4; i++)
	{
		for(int j = 0; j<4; j++)
			state[i][j] = input[i+4*j];
	}

	int Nr = words.size()/4 - 1;
	__addRoundKey_transform__(state,words,4*Nr);
	int round = Nr-1;

	while(round >=1)
	{
		__shiftRows_inv_transform__(state);
		__subBytes_transform__(state,true);
		__addRoundKey_transform__(state,words,round*4);
		__mixColumns_inv_transform__(state);
		round--;
	}
	
	__shiftRows_inv_transform__(state);
	__subBytes_transform__(state,true);
	__addRoundKey_transform__(state,words,0);

	std::vector<BYTE> output(input.size());

	for(int i=0; i<4; i++){
		for(int j=0; j<4; j++)
			output[i + 4*j] = state[i][j];
	}

	return output;	
	
}
std::string crypto_AES::__hex_transform__(std::vector<BYTE> &bytes)
{
	std::stringstream ss;
	int temp;
	for(int b_i = 0; b_i < bytes.size(); b_i++)
	{
		temp = bytes[b_i];
		ss << std::setfill('0')
		   << std::setw(2)
		   << std::hex
		   << temp;
	}
	return ss.str();
}
std::string crypto_AES::__ascii_transform__(std::vector<BYTE> &bytes)
{
	std::string ascii="";
	int temp;
	for(int b_i = 0; b_i < bytes.size(); b_i++)
	{
		temp = bytes[b_i];
		ascii += std::string(1,(char)temp);
	}

	return ascii;
}
std::vector<BYTE> crypto_AES::__BYTE_transform__(std::string str,
						 STRING_TYPE str_type)
{
	std::vector<BYTE> bytes;
	unsigned int temp;
	switch(str_type)
	{
		case HEX_0:
			{
				if(str.size()%2!=0)
				{
					std::cerr<<"Size incompatible!! Aborting!"
						 <<std::endl;
					exit(1);
				}
				
				for(int str_i = 0; str_i<str.size(); str_i+=2)
				{
					std::stringstream ss;
					ss << std::hex << str.substr(str_i,2);
					ss >> temp;
					bytes.push_back(temp); 
				}	
				break;
			
			}

		case ASCII_1:
			{
				for(int str_i = 0; str_i < str.size(); str_i++)
				{
					temp = str[str_i];
					bytes.push_back(temp);
				}
		
			}
			break;

		default: 
				std::cerr<<"String "<<str<<" with type "<<str_type<<" not defined!!! Aborting!"
					 <<std::endl;

				exit(1);
	}

	return bytes;
}
std::vector<BYTE> crypto_AES::__getNextBlock__()
{
	std::vector<BYTE> bytes;
	switch(this->m_type)
	{
		case HEX_0:
			if(this->input.size() < 32)
			{
				std::cerr<<"Incompatible size!! Aborting!!"
					 <<std::endl;
				exit(1);
			}
			bytes = __BYTE_transform__(this->input.substr(0,32),HEX_0);
			this->input = this->input.substr(32);
			break;

		case ASCII_1:
			if(this->input.size() < 16)
			{
	
				std::cerr<<"Incompatible size!! Aborting!!"
					 <<std::endl;
				exit(1);
			}
			bytes = __BYTE_transform__(this->input.substr(0,16),ASCII_1);
			this->input = this->input.substr(16);
			break;

		default:
			std::cerr<<"String type not defined!! Aborting"
				 <<std::endl;
			exit(1);
	}

	return bytes;
}

void crypto_AES::__pad_message__(PAD_TYPE pad_type)
{
	std::string pad_char;
	int pad_num;
	std::stringstream ss;
	std::string pad;
	switch(pad_type)
	{
		case NORM_0:
			if(this->m_type == HEX_0)
			{
				if(this->input.size()%32 == 0)
					return;

				pad_num=32 - input.size()%32;
				pad_char = std::string("0");
			}
			else if(this->m_type == ASCII_1)
			{
				if(this->input.size()%16 == 0)
					return;

				pad_num = 16 - input.size()%16;
				pad_char = std::string(1,'\0');
			}
			
			break;
		case PKCS5:
			if(this->m_type == HEX_0)
			{
				pad_num = 32 - input.size()%32;
				if(pad_num%2 == 1 )
				{
					std::cerr<<"PKCS5 padding cannot be done! Hence reverting to normal padding"
						 <<std::endl;
					return __pad_message__(NORM_0);
				}
				pad_num /= 2;
				ss << std::setfill('0')
				   << std::setw(2)
				   <<std::hex << pad_num;
				pad_char = ss.str();	
			}	
			else if(this->m_type == ASCII_1)
			{
				pad_num = 16 - input.size()%16;
				pad_char = std::string(1,(char)pad_num);
			}

			break;
		default:
			std::cerr<<"Pad type not defined!! Aborting!!"
				 <<std::endl;
			exit(1);
			break;
	}

	while(pad_num--)
	{
		this->input += pad_char;
	}
}
std::string crypto_AES::encrypt(std::string mess,
				STRING_TYPE mess_type,
				std::string key,
				STRING_TYPE key_type,
				ENCRYPTION_MODE enc_mod,
				std::string iv,
				STRING_TYPE iv_type,
				PAD_TYPE pad_type)

{
	this->output = "";

	if( mess_type >= STRING_TYPE_MAX || key_type >= STRING_TYPE_MAX)
	{
			
		std::cerr<<"Types out of range!! aborting!"<<std::endl;
		return std::string();
	}

	else if( enc_mod >= ENCRYPTION_MODE_MAX )
	{
		std::cerr<<"Encryption mode out of range!! aborting!"
			 <<std::endl;
		return std::string();
	}

	else if( mess_type == HEX_0 && mess.size()%2 )
	{
		std::cerr<<"Hex messages should be of even length!! aborting!"
		   	 <<std::endl;
		return std::string();
	}
	else if ( iv_type == STRING_TYPE_MAX && enc_mod == CBC_1 )
	{
		std::cerr<<"Intialization vector not provided!! aborting!"
			 <<std::endl;
		return std::string();
	}

	std::vector<BYTE> key_in_bytes = __BYTE_transform__(key,key_type);
	
	switch(key_in_bytes.size())
	{
		case 16:
		case 24:
		case 32:
			break;
		default:
			std::cerr<<"Key size not supported!! Aborting!!"
				 <<std::endl;
			exit(1);
	}

	this->input = mess;
	this->m_type = mess_type;

	__pad_message__(pad_type);
	this->secretKey = __roundKeyGen__(key_in_bytes);

	
	std::vector<BYTE> mess_block;
	std::vector<BYTE> enc_block;
	switch(enc_mod)
	{
		case ECB_0:
			{
				while(1)
				{
					mess_block = __getNextBlock__();
					enc_block = __enc_block__(mess_block,
								  this->secretKey);
					this->output += __hex_transform__(enc_block);

					if( this->input.size() == 0)
						break;
				}
				break;
			}

	
		case CBC_1:
			{
				enc_block = __BYTE_transform__(iv,iv_type);
				if(enc_block.size()!=16)
				{
					std::cerr<<"IV size not compatible!! Aborting!!"
						 <<std::endl;
					exit(1);
				}	

				this->output += __hex_transform__(enc_block);	
			
				while(1)
				{
					mess_block = __getNextBlock__();
					mess_block = __xor_word__(mess_block,
								  enc_block);
					enc_block = __enc_block__(mess_block,
								  this->secretKey);
			
					this->output += __hex_transform__(enc_block);
					if( this->input.size() == 0 )
						break;
				}	

				break;
			}	

		default:
			std::cerr<<"Wrong choice input"<<std::endl;
			exit(1);
	}

	
	
	return this->output;
}

 
std::string crypto_AES::decrypt(std::string mess,
				STRING_TYPE mess_type,
				std::string key,
				STRING_TYPE key_type,
				ENCRYPTION_MODE enc_mod,
				PAD_TYPE pad_type)
{
	this->output = "";

	if( mess_type >= STRING_TYPE_MAX || key_type >= STRING_TYPE_MAX)
	{
			
		std::cerr<<"Types out of range!! aborting!"<<std::endl;
		return std::string();
	}

	else if( enc_mod >= ENCRYPTION_MODE_MAX )
	{
		std::cerr<<"Encryption mode out of range!! aborting!"
			 <<std::endl;
		return std::string();
	}

	else if( mess.size()%32!=0 )
	{
		std::cerr<<"Encrypted hex messages should be a multiple of 32 bits!! aborting!"
		   	 <<std::endl;
		return std::string();
	}
	else if ( mess.size() <=32  && enc_mod == CBC_1 )
	{
		std::cerr<<"Message size very small!! aborting!"
			 <<std::endl;
		return std::string();
	}

	std::vector<BYTE> key_in_bytes = __BYTE_transform__(key,key_type);
	
	switch(key_in_bytes.size())
	{
		case 16:
		case 24:
		case 32:
			break;
		default:
			std::cerr<<"Key size not supported!! Aborting!!"
				 <<std::endl;
			exit(1);
	}

	this->input = mess;
	this->m_type = HEX_0;

	this->secretKey = __roundKeyGen__(key_in_bytes);

	
	std::vector<BYTE> mess_block;
	std::vector<BYTE> dec_block;
	std::vector<BYTE> temp;
	switch(enc_mod)
	{
		case ECB_0:
			{
				while(1)
				{
					mess_block = __getNextBlock__();
					dec_block = __dec_block__(mess_block,
								  this->secretKey);
					
					if(mess_type == HEX_0)
						this->output += __hex_transform__(dec_block);

					else if(mess_type == ASCII_1 )
						this->output += __ascii_transform__(dec_block);
					if( this->input.size() == 0)
						break;
				}
				break;
			}

	
		case CBC_1:
			{
				mess_block = __getNextBlock__();

				while(1)
				{
					temp = mess_block;
					mess_block = __getNextBlock__();
					dec_block = __dec_block__(mess_block,
								  this->secretKey);
			
					dec_block = __xor_word__(dec_block,temp);
					if(mess_type == HEX_0 )
						this->output += __hex_transform__(dec_block);
					else if(mess_type == ASCII_1 )
						this->output += __ascii_transform__(dec_block);

					if( this->input.size() == 0 )
						break;
				}	

				break;
			}	

		default:
			std::cerr<<"Wrong choice input"<<std::endl;
			exit(1);
	}

	if(pad_type == PKCS5)
	{
		int count = 0,n;
		n = this->output.size();
		std::stringstream ss;
		ss << std::hex << this->output.substr(n-2);
		ss >> count;

		this->output = this->output.substr(0,n-count*2);
	}
	
	return this->output;
}
