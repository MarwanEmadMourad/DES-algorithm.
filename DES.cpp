#include <iostream>
#include <vector>
#include <algorithm>
#include <math.h> 

#ifdef __GNUC__
# define __rdtsc __builtin_ia32_rdtsc
#else
# include<intrin.h>
#endif


typedef unsigned long long ull;

using namespace std;


ull to_ull(string s)
{
	ull ans = 0;
	int counter = 0;
	ull temp = 0 ;
	for (int i = s.size()-1 ; ~i ; i--) {
		char c = s[i] ;
		if (c >= '0' && c<= '9') {
			c -= 48;
		}
		else if (c >= 'A' && c <= 'F') {
			c -= 55;
		}
		temp = ull(c);
		temp = temp << counter;
		ans |= temp;
		counter += 4;
	}
	return ans;
}

ull permute(ull in, vector <int> &table,int in_size , int out_size) {
	ull out = 0;
	int n = table.size();
	for (int i = 0; i < out_size; i++) {
		out |= (in >> (in_size - table[out_size-1-i]) & 1) <<i;
	}
	return out;
}

unsigned int shift_left_rotate(unsigned int s, int &shifts)
{
	unsigned int shift_mask = (shifts == 1) ? 134217728 : 201326592;
	unsigned int val = (s & shift_mask) >> (28-shifts);
	s &= ~shift_mask;
	s = s << shifts;
	s |= val;
	
	return s;
}

ull xor_ (ull a, ull b) {
	return (a ^ b);
}


ull Encrypt(string &plain_text, vector<ull> &bin_pkeys)
{
	// converting plain text from hexadecimal to binary
	ull Plain_text = to_ull(plain_text);

	// Initial Permutation Table
	vector <int> initial_permutation_table = { 58, 50, 42, 34, 26, 18, 10, 2,
							60, 52, 44, 36, 28, 20, 12, 4,
							62, 54, 46, 38, 30, 22, 14, 6,
							64, 56, 48, 40, 32, 24, 16, 8,
							57, 49, 41, 33, 25, 17, 9, 1,
							59, 51, 43, 35, 27, 19, 11, 3,
							61, 53, 45, 37, 29, 21, 13, 5,
							63, 55, 47, 39, 31, 23, 15, 7 };
	// Initial Permutation
	Plain_text = permute(Plain_text, initial_permutation_table,64,64);
	// Dividing Plain text into two 32-bit parts
	unsigned int left = int (Plain_text>>32);
	unsigned int right = int (Plain_text);	


	// Expansion lookup table for the right part (32 bit --> 48 bit)
	vector<int> exp_table = { 32, 1, 2, 3, 4, 5, 4, 5,
					6, 7, 8, 9, 8, 9, 10, 11,
					12, 13, 12, 13, 14, 15, 16, 17,
					16, 17, 18, 19, 20, 21, 20, 21,
					22, 23, 24, 25, 24, 25, 26, 27,
					28, 29, 28, 29, 30, 31, 32, 1 };

	// S-box look-up Table (inside f-function) 4x16 table and we have 8 s-boxs so 4x16x8  
	int s[8][4][16] = { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
						0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
						4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
						15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 },
						{ 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
						3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
						0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
						13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },

						{ 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
						13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
						13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
						1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 },
						{ 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
						13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
						10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
						3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 },
						{ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
						14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
						4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
						11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 },
						{ 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
						10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
						9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
						4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 },
						{ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
						13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
						1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
						6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 },
						{ 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
						1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
						7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
						2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

	// Straight Permutation Table (last step in f-function)
	vector<int> per = { 16, 7, 20, 21,
					29, 12, 28, 17,
					1, 15, 23, 26,
					5, 18, 31, 10,
					2, 8, 24, 14,
					32, 27, 3, 9,
					19, 13, 30, 6,
					22, 11, 4, 25 };

	int counter = 28;
	// 16 iteration for each round in the 16 rounds
	for (int i = 0; i < 16; i++) {
		// Converting 32 bits (right-part) into 48 bits
		ull right_expanded = permute(right, exp_table,32,48);

		// XOR partial-key and right_expanded
		ull x = xor_(bin_pkeys[i] , right_expanded);
		// S-boxes output
		int op = 0 ;

		// 8 iterations for each of the 8 s-boxes
		for (int i = 0; i < 8; i++) {
			// each time we read 6-bits from 42 to 48
			ull _6bits = (x & 277076930199552);
			// then we transfer the read value to be at bits 0-5
			_6bits = _6bits >> 42;
			// shitfing the output each iteration 6 bits to read the next 6 bits  
			x = x << 6;

			int row = 0, col = 0;
			// 33 --> row selector mask
			row = _6bits & 33 ;
			if (row == 32 || row == 33) {
				row -= 30;
			}
			// 30 --> col selector mask
			col = (_6bits&30)>>1;

			// 4-bit value that is the result of each s-box  
			int val = s[i][row][col];
			// adding each resulted 4-bit to our output
			op |= (val << counter);
			counter -= 4;
		}
		// last permutaion inside f-function
		op = permute(op, per,32,32);

		// XOR left part with output of f-function
		x = xor_(op, left);
		left = x;
		// swap both parts unless it's the last round
		if (i != 15) {
			left = right;
			right = x;
		}
	}

	// Combination of 2 32-bit parts to get the encrypted 64 bit cipher
	ull cipher = 0;
	cipher |= left;
	cipher = cipher << 32;
	cipher |= right;


	// Final Permutation look-up Table
	vector <int> final_perm = { 40, 8, 48, 16, 56, 24, 64, 32,
						39, 7, 47, 15, 55, 23, 63, 31,
						38, 6, 46, 14, 54, 22, 62, 30,
						37, 5, 45, 13, 53, 21, 61, 29,
						36, 4, 44, 12, 52, 20, 60, 28,
						35, 3, 43, 11, 51, 19, 59, 27,
						34, 2, 42, 10, 50, 18, 58, 26,
						33, 1, 41, 9, 49, 17, 57, 25 };

	// making the final permutation on the binary cipher
	cipher = permute(cipher, final_perm,64,64);
	return cipher ;
}



int main(int argc, char* argv[])
{
	// pt is plain text
	string op = argv[1], plain_text = argv[2], skey = argv[3];
	/*string plain_text = "7A6C731D22347676";
	string skey = "1323445A6D788381";*/
	// getting 64-bit key from hexa key
	ull key = to_ull(skey);

	//look-up table that permutes the 64-bit key and also reduce it to 56-bit key
	vector <int> keyp = { 57, 49, 41, 33, 25, 17, 9,
					1, 58, 50, 42, 34, 26, 18,
					10, 2, 59, 51, 43, 35, 27,
					19, 11, 3, 60, 52, 44, 36,
					63, 55, 47, 39, 31, 23, 15,
					7, 62, 54, 46, 38, 30, 22,
					14, 6, 61, 53, 45, 37, 29,
					21, 13, 5, 28, 20, 12, 4 };

	// getting 56 bit key from 64 bit key
	key = permute(key, keyp,64,56);

	// look-up Table that permutes the 56-bit key and also gets 48-bit key from 56-bit key 
	vector<int> key_compression = { 14, 17, 11, 24, 1, 5,
						3, 28, 15, 6, 21, 10,
						23, 19, 12, 4, 26, 8,
						16, 7, 27, 20, 13, 2,
						41, 52, 31, 37, 47, 55,
						30, 40, 51, 45, 33, 48,
						44, 49, 39, 56, 34, 53,
						46, 42, 50, 36, 29, 32 };

	// deviding the key into two 28-bit parts in 32-bit ints
	unsigned int left = (key>>28);
	unsigned int right = ((key << 36)>>36);
	
	// partial keys for each round in binary
	vector<ull> bin_pkeys;
	// partial keys for each round in ull variables
	for (int i = 0; i < 16; i++) {
		// Shifting the two 28-bit key parts
		int shift_amount = 2;
		if (i + 1 == 1 || i + 1 == 2 || i + 1 == 9 || i + 1 == 16)
			shift_amount = 1;
		left = shift_left_rotate(left, shift_amount);
		right = shift_left_rotate(right, shift_amount);

		// Concatinating left and right key parts to get the 56-bit key in 64-bit variable
		ull _56bit_Key = 0;
		_56bit_Key |= ull(left);
		_56bit_Key = _56bit_Key << 28 ;
		_56bit_Key |= ull(right);

		// getting the 48-bit key from 56-bit key that will be inputed to the f-function
		ull _48bit_key = permute(_56bit_Key, key_compression, 56,48);

		// storing the partial keys for each round
		bin_pkeys.push_back(_48bit_key);
	}
	if (op == "encrypt") {
		long long t1 = __rdtsc();
		ull cipher = Encrypt(plain_text, bin_pkeys);
		long long t2 = __rdtsc();
		printf("cipher: %016llX\n", cipher);
		//cout << "cipher: " << cipher << endl;
		cout << "Number of Cycles: " << (t2 - t1);
	}
	if (op == "decrypt") {
		// decryption is just the same as the encryption but you reverse the partial keys order
		reverse(bin_pkeys.begin(), bin_pkeys.end());
		long long t1 = __rdtsc();
		ull text = Encrypt(plain_text, bin_pkeys);
		long long t2 = __rdtsc();
		printf("plain text: %016llX\n", text);
		//cout << "plain text: " << text;
		cout << "Number of Cycles: " << (t2 - t1);
	}
}


