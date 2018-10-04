#include <iostream>
#include <vector>
#include "constants_AES.h"
#define 

void subBytes_transform(vector< vector< uint8_t > > &state )
{
	uint8_t row, col;
	uint8_t mask = 0x0f;
	uint8_t s;
	for(int i=0; i<4; i++)
	{
		for(int j=0; j<4; j++)
		{
			s = (state[i][j]);
			row = (s & (mask << 4 ) >> 4);
			col = s & mask;
			state[i][j] = S_box[row][col];
		}
	}
}

void shiftRow_left(vector< uint8_t > &row )
{
	uint8_t temp;
	temp   = row[0];
	row[0] = row[1];
	row[1] = row[2];
	row[2] = row[3];
	row[3] = temp;
}
void shiftRows_transform(vector< vector< uint8_t > > &state )
{
	shiftRow_left(state[1]);
	shiftRow_left(state[2]);
	shiftRow_left(state[2]);
	shiftRow_left(state[3]);
	shiftRow_left(state[3]);
	shiftRow_left(state[3]);
}

void mixColumns_transform(vector< vector< uint8_t > > &state )
{
	for(int j = 0; j < 4; j++ )
	{
		state[0][j] = (2 * state[0][j]) ^ ( 3 * state[1][j] ) ^ ( 1 * state[2][j] ) ^ ( 1 * state[3][j] );
		state[1][j] = (1 * state[0][j]) ^ ( 2 * state[1][j] ) ^ ( 3 * state[2][j] ) ^ ( 1 * state[3][j] );
		state[2][j] = (1 * state[0][j]) ^ ( 1 * state[1][j] ) ^ ( 2 * state[2][j] ) ^ ( 3 * state[3][j] );
		state[3][j] = (3 * state[0][j]) ^ ( 1 * state[1][j] ) ^ ( 1 * state[2][j] ) ^ ( 2 * state[3][j] );
	}
}

void addRoundKey_transform(vector< vector< uint8_t > > &state, vector< vector< uint8_t > > &roundKey )
{

}


int main()
{

}
