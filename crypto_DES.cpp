#include <iostream>
#include <bitset>
#include <vector>
#include "constant.h"
#include "crypto_DES.h"
#define ll unsigned long long int


crypto_DES::crypto_DES()
{

}

// it is assumed that the string is of correct size
ll crypto_DES::__convert2Dec__(std::string str, STRING_TYPE str_type)
{
	ll dec = 0;
	if(str_type == HEX_0 )
	{
		if( str.size() != 16 )
		{
			std::cerr<<"Wrong string size!! aborting!"<<std::endl;
			exit(1);
		}
		std::stringstream ss;
		ss << std::hex << str;
		ss >> dec;
	}
	else if(str_type == ASCII_1 )
	{
		if( str.size() != 8 )
		{
			std::cerr<<"Wrong string size!! aborting!"<<std::endl;
			exit(1);
		}
		for( int str_i = 0; str_i < 8; str_i++ )
		{
			dec = dec << 8;
			dec = dec | str[str_i];
		}
	}

	return dec;
}
ll crypto_DES::__roundFunction__(ll roundKey, ll data)
{

	
	
	//expanding data to 48 bits
	ll expData=0;
	ll currBits;	
	ll mask,one;

	mask = 15;
	mask = mask<<60;
	one = 1;

	bool firstBit = (data & (one<<31));
	bool lastBit = (data & 1);
	data = data<<32;
	
	for(int i=0;i<8;i++)
	{
		currBits = (mask) & data;
		data = data<<4;
		
		currBits = currBits >> 59;
	
	 	if( data & (one<<63) )
			currBits = currBits | 1;

		if( expData & 2 )
			currBits = currBits | (1<<5);

		expData = expData << 6;
		expData = expData | currBits;	
		
	}
	
	if(firstBit)
		expData = expData | 1;
	if(lastBit)
		expData = expData | (one<<47);

	expData = expData & 281474976710655;
	
	ll xorData = expData ^ roundKey;

	
	ll row, col;
	ll rowMask, colMask;
	rowMask = 33;
	colMask = 30;
	ll encData=0;
	ll bit;
	/*
			    col
                             |
			  ___|___	
			1 0 1 1 0 0
			|         |
			----|------
			    |
			   row
	*/
	for(int i=0;i<8;i++)
	{
		row = rowMask & xorData;
		col = colMask & xorData;
		
		col = col>>1;
		row = (row>>4);
		if(xorData & 1 )
			row = row | 1;
		xorData = xorData>>6;

		bit = S_box[7-i][row][col];
		encData = encData >> 4;	 
		encData = encData | (bit<<60);
	}		

	encData = encData >> 32;
		
	ll perData = 0;
	ll pos;
	for(int i=0;i<32;i++)
	{
		pos = straight_permut_box[i];
		if( encData & (one << (32 - pos)))
			perData = perData | (one << (31 - i));
	}	
		
	return perData;
}

ll crypto_DES::__permut__(ll data, bool inverse=false)
{

	int in = 0;
	if(inverse)
		in = 1;
	
	ll newData = 0;
	int pos;
	ll one = 1;
	for(int i=0; i<64; i++)
	{
		pos = permut_box[in][i];
		if(data & (one << (64-pos)) ){
			newData = newData | (one << (63 - i));
		}
	}

	return newData;
}

ll crypto_DES::__cirShift__(ll data)
{
	ll mask = 1;
	mask = mask<<27;
	if(data & mask)
	{
		data = data<<1;
		data = data | 1;
	}
	else 
		data = data<<1;

	data = data & (268435455);
	return data;
}


ll crypto_DES::__roundKeyGen__(ll &key, int &round)
{
	ll mask = 268435455; // 2 ^ 28 - 1
	ll left = (key & (mask<<28))>>28;
	ll right = (key & mask);

	int count = 2;
	
	if(round==1 || round==2 || round==9 || round==16 )
		count = 1;
	round++;
	
	while(count--)
	{
		left = __cirShift__(left);
		right = __cirShift__(right);
	}

	key = (left<<28) | right;
	ll roundKey = 0;
	ll one = 1;
	int pos;
	for(int i=0;i<48;i++)
	{
		pos = C_box[i];
		if( key & (one << (56-pos)))
			roundKey = roundKey | (one << (47 - i));
	}  	

	return roundKey;
}

ll crypto_DES::__parity_drop__(ll key)
{
	ll redKey=0;
	ll one = 1;
	int pos;
	for(int i=0;i<56;i++)
	{
		pos = Parity_box[i];
		if( key & (one << (64 - pos)))
			redKey = redKey | (one << (55 - i));
	}

	return redKey;
}

ll crypto_DES::__enc_block__(ll key, ll data)
{
	key = __parity_drop__(key);
	data = __permut__(data);
	int round=1;
	ll mask = 4294967295;
	ll left = (data & (mask<<32))>>32;
	ll right = (data & mask);
	ll temp;
	ll roundKey;
	ll roundOut;
	while(round<17)
	{
		roundKey = __roundKeyGen__(key,round);
		temp = left;
		left = right;
		right = (temp ^ __roundFunction__(roundKey, right));
	}
	data= (right<<32) | left;
	return __permut__(data,true);
}

ll crypto_DES::__getNextBlock__()
{
	ll block;
	block = 0;
	switch(this->m_type)
	{
		case HEX_0:
			{
			if( this->input.size() < 16 )
			{
				std::cerr<<"Skipping last block!!" 
					 <<std::endl;
				return 0;
			} 
			block = __convert2Dec__(input.substr(0,16),HEX_0);
			this->input = this->input.substr(16);
			break;
			}
		case ASCII_1:
			{
			if( this->input.size() < 8 )
			{
				std::cerr<<"Skipping last block!!"
					 <<std::endl;
				return 0;
			} 
			block = __convert2Dec__(input.substr(0,8),ASCII_1);
			this->input = this->input.substr(8);
			break;
			}
		default: 
			return 0;
	}
	
	return block;
}

void crypto_DES::__pad_message__()
{
	if( this->input.size()%16 == 0 )
		return ;
	int pad_len = 16 - input.size()%16 ;
	std::string pad(pad_len, '0');
	this->input += pad;
}
std::string crypto_DES::encrypt(std::string mess, std::string key, 
				STRING_TYPE mess_type, STRING_TYPE key_type,
				ENCRYPTION_MODE enc_mod,
				std::string iv,
				STRING_TYPE iv_type)
	{
		
		if( mess_type >= STRING_TYPE_MAX || key_type >= STRING_TYPE_MAX)
		{
			std::cerr<<"Type out of range!! aborting!"<<std::endl;
			return std::string();
		}

		if( enc_mod >= ENCRYPTION_MODE_MAX )
		{
			std::cerr<<"Encryption mode out of range!! aborting!"
				 <<std::endl;
			return std::string();
		}

		if( mess_type == HEX_0 && mess.size()%2 )
		{
			std::cerr<<"Hex messages should be of even length!! aborting!"
				<<std::endl;
			return std::string();
		}
		if ( iv_type == STRING_TYPE_MAX && enc_mod == CBC_1 )
		{
			std::cerr<<"Intialization vector not provided!! aborting!"
				 <<std::endl;
			return std::string();
		}
		
		switch(key_type)
		{
			case HEX_0:
				{
				if(key.size() != 16 )
				{
					std::cerr<<"Wrong key size!! aborting!"
						 <<std::endl;

					return std::string();
				}
				this->secretKey = __convert2Dec__(key,HEX_0);
				break;
				}
		        case ASCII_1:
				{
				if( key.size() != 8 )
				{
					std::cerr<<"Wrong key size!! aborting!"
						 <<std::endl;

					return std::string();
				}		

				this->secretKey = __convert2Dec__(key,ASCII_1);;
				break;
				}
			default:
				return 0;
		}
		this->input = mess;
		this->m_type = mess_type;

		__pad_message__();
		ll mess_block;
		ll enc_block;	
		std::stringstream ss;
		switch(enc_mod)
		{
			case ECB_0: 
				{	
				while(1)
				{
					mess_block = __getNextBlock__();
					enc_block = __enc_block__(this->secretKey,
								mess_block);

					ss.str("");
					ss << std::hex << enc_block;
					this->output += ss.str();
					if( this->input.size() < 16 )
						break;
				}
				break;
				}
			case CBC_1:
				{
				
				mess_block = __convert2Dec__(iv,iv_type);
				enc_block = mess_block;
				ss.str("");
				ss << std::hex << enc_block;
				this->output += ss.str();
				while(1)
				{
					mess_block = __getNextBlock__() ^ enc_block;
					enc_block = __enc_block__(this->secretKey, mess_block);

					ss.str("");
					ss << std::hex << enc_block;
					this->output += ss.str();
					if( this->input.size() < 16 )
						break;
				}
				break;
				}
				
			default:
				return std::string();	
		}
		return this->output;
}			
