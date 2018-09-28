#include <iostream>
#include <bitset>
#include <vector>
#include "constant.h"
//#include "constants.h"
#define ll unsigned long long int
using namespace std;
/******************************************************************************

roundKey: Key for the round
data: data used as input to the round function

Note:

48 least signifcant bits of roundKey are used for it. The rest are ignored.
32 least signifcant bits of data are considered
******************************************************************************/
ll roundFunction(ll roundKey, ll data)
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

ll permut(ll data, bool inverse=false)
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

ll cirShift(ll data)
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
/******************************************************************************

key: Key for the current round
round: round for which the key needs to be generated

Note:
After this round, key and round will be updated on it's own.
The key is in the 56 least significant bits.
******************************************************************************/
ll roundKeyGen(ll &key, int &round)
{
	ll mask = 268435455; // 2 ^ 28 - 1
	ll left = (key & (mask<<28))>>28;
	ll right = (key & mask);

	int count = 2;
	if(round==1 || round==2 || round==9 || round==16 )
		count = 1;
	
	while(count--)
	{
		left = cirShift(left);
		right = cirShift(right);
	}

	key = (left<<28) | right;
	round++;
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

ll parity_drop(ll key)
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

ll enc_DES(ll key, ll data)
{
	key = parity_drop(key);
	cout<<"Data before initi. permutation: "<<std::hex<<data<<endl;
	data = permut(data);
	int round=1;
	ll mask = 4294967295;
	ll left = (data & (mask<<32))>>32;
	ll right = (data & mask);
	ll temp;
	ll roundKey;
	cout<<"Data after initial permutation: "<<std::hex<<data<<endl;
	cout<<"L0: "<<std::hex<<left<<" R0: "<<std::hex<<right<<endl;
	while(round<17)
	{
		cout<<round<<": ";
		roundKey = roundKeyGen(key,round);
		temp = right;
		right = left ^ roundFunction(roundKey,right);
		left = temp;
		cout<<std::hex<<left<<" "<<std::hex<<right<<" "<<std::hex<<roundKey<<endl;
	}
	data= (left<<32) | right;
	return permut(data,true);
}
int main()
{
	ll key;
	ll data;
	ll enc;

	cin>>data>>key;
	enc = enc_DES(key,data);
	cout<<enc<<endl;

//	ll roundKey, right;
//	cin>>roundKey>>right;
//	cout<<std::hex<<(roundFunction(roundKey,right))<<endl;	
	
}
