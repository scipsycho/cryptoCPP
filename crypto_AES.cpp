#include <iostream>
#include <vector>
#include "constants_AES.h"
#define 

void subBytes_transform(vector< vector< uint8_t > > &state )
{
	uint8_t row, col;
	uint8_t mask = 0x0f;
	uint8_t s;
	int n = state.size();
	int m = state[0].size();
	for(int i=0; i<n; i++)
	{
		for(int j=0; j<m; j++)
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
	int n = row.size();
	
	for(int i=0; i<n-1;i++)
		row[i] = row[i+1];

	row[n-1] = temp;
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
	for(int j = 0; j < state[0].size(); j++ )
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
