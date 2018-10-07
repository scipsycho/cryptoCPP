#include <iostream>
#include <vector>
#include <cmath>
#include <iomanip>
using namespace std;

class BYTE
{
	public:
	uint8_t byte;

	BYTE()
	{
		byte = 0;
	}	
	BYTE(int t)
	{
		byte = (uint8_t)t;
	}

	BYTE(unsigned int t)
	{
		byte = (uint8_t)t;
	}
	BYTE(uint8_t t)
	{
		byte = t;
	}
	BYTE operator^(const BYTE &a)
	{	
		return BYTE(byte ^ (a.byte));
	}
	friend BYTE operator*(const int a, const BYTE &b)
	{
		return BYTE(a) * b;
	}
	friend BYTE operator*(const BYTE &a, const int b)
	{
		return a * BYTE(b);
	}
	BYTE operator*(const BYTE &a)
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
		/*		
		unsigned int dividend, divisor,quotient, remainder;
		dividend = temp;
		divisor = 283;
		int max1 = floor(log2(dividend))+1;
		int max2 = floor(log2(divisor))+1;
		while(max1 >= max2)
		{
			dividend = dividend ^ ( divisor << (max1 - max2) );
			max1 = floor(log2(dividend))+1;
		}
		temp = dividend;
		*/
		return BYTE(temp);	
	}


	BYTE operator << (std::size_t n)
	{
		return BYTE(byte << n);
	}
	
	BYTE operator << (int n)
	{
		return BYTE(byte << n);
	}
	BYTE operator >> (std::size_t n)
	{
		return BYTE(byte >> n);
	}

	BYTE operator >> (int n)
	{
		return BYTE(byte >> n);
	}
	BYTE operator & (const BYTE &a)
	{
		return BYTE(byte & a.byte);
	}

	BYTE operator = (const BYTE &b)
	{
		byte = b.byte;
		return BYTE(byte);
	}
	
	operator int()
	{
		return (int)byte;
	}
};
#include "constants_AES.h"
void subBytes_transform_word(vector< BYTE > &word)
{
	BYTE mask = 0x0f;
	BYTE row,col;
	BYTE byte;
	for(int i=0; i< word.size(); i++)
	{
		byte = word[i];
		row = ( byte & ( mask << 4 ) ) >>4;
		col = byte & mask;
		word[i] = S_box[row][col];
	}
}

vector<BYTE> xor_word(vector< BYTE > &word1, vector< BYTE > &word2)
{
	if ( word1.size() != word2.size() )
	{
		std::cerr<<"Size Incompatible!! Aborting!"<<std::endl;
		exit(1);
	}

	int n = word1.size();
	vector< BYTE > word(n,0);

	for(int i=0; i<n; i++)
		word[i] = word1[i] ^ word2[i];

	return word;
} 
void subBytes_transform(vector< vector< BYTE > > &state )
{
	int n = state.size();
	int m = state[0].size();
	for(int i=0; i<n; i++)
	{
		subBytes_transform_word(state[i]);
	}
}

void shiftRow_left(vector< BYTE > &row )
{
	BYTE temp;
	temp   = row[0];
	int n = row.size();
	
	for(int i=0; i<n-1;i++)
		row[i] = row[i+1];

	row[n-1] = temp;
}
void shiftRows_transform(vector< vector< BYTE > > &state )
{
	shiftRow_left(state[1]);
	shiftRow_left(state[2]);
	shiftRow_left(state[2]);
	shiftRow_left(state[3]);
	shiftRow_left(state[3]);
	shiftRow_left(state[3]);
}

void mixColumns_transform(vector< vector< BYTE > > &state )
{
	vector< BYTE > state_col(4);
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
void show_word(vector<BYTE> &word)
{
	int temp;
	for(int j=0; j<word.size();j++){
		temp=word[j];
		std::cout<<setfill('0')<<setw(2)<<std::hex<<temp;
	}
	std::cout<<" ";
}
vector< vector<BYTE> >  roundKeyGen(vector<BYTE> &key)
{
	int i=0;
	
	int Nk = key.size() / 4;
	int Nr;
	vector<BYTE> temp;
	switch(Nk)
	{
		case 4: Nr = 10;
			break;
		case 6: Nr = 12;
			break;
		case 8: Nr = 14;
			break;
	}
	vector< vector<BYTE> > words(4*(Nr+1),vector<BYTE>(4,0));
	while( i < Nk )
	{
		for(int j = 0; j < 4; j++ )
			words[i][j] = key[4*i + j]; 	
		i++;
	}

	while( i < 4 * ( Nr + 1 ))
	{
		std::cout<<setw(2)<<i<<": ";
		temp = words[i-1];
		if ( i % Nk == 0)
		{
			shiftRow_left(temp);
			show_word(temp);
			subBytes_transform_word(temp);
			show_word(temp);
			temp[0] = temp[0] ^ R_con[i/Nk -1];
			show_word(temp);   
		}
		else if( ( Nk > 6 ) && (i % Nk == 4) ){
			subBytes_transform_word(temp);
			show_word(temp);
		}
		words[i] = xor_word(words[i-Nk],temp);
		i++;
		std::cout<<endl;
	}

	return words;
	
}
void addRoundKey_transform(vector< vector< BYTE > > &state,vector<vector<BYTE> > &words, int s )
{
	for(int j = 0; j< state[0].size(); j++)
	{
		for(int i=0; i < state.size(); i++)
			state[i][j] = state[i][j] ^ words[s+j][i];
	}
}
void show(vector<vector<BYTE> > &state,string s)
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
	std::cout<<endl;
}
vector<BYTE> enc_block(vector<BYTE> &input,
			vector<vector<BYTE> > &words)
{
	vector<vector<BYTE> > state(4,vector<BYTE>(4,0));
	for(int i = 0; i<4; i++)
	{
		for(int j = 0; j<4; j++)
			state[i][j] = input[i+4*j];
	}

	int Nr = words.size()/4 - 1;
	addRoundKey_transform(state,words,0);
	int round = 1;

	while(round < Nr)
	{
		show(state,"round[" + to_string(round) + "]");
		subBytes_transform(state);
		show(state,"subBytes");
		shiftRows_transform(state);
		show(state,"shitrow ");
		mixColumns_transform(state);
		show(state,"mixcol  ");
		addRoundKey_transform(state,words,round*4);
		show(state,"addkey  ");
		round++;
	}
	
	subBytes_transform(state);
	shiftRows_transform(state);
	addRoundKey_transform(state,words,round*4);

	vector<BYTE> output(input.size());

	for(int i=0; i<4; i++){
		for(int j=0; j<4; j++)
			output[i + 4*j] = state[i][j];
	}

	return output;	
	
} 
int main()
{
}
