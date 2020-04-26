#include <stdint.h>
#include <string.h>
#include <iostream>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include "hmac-sha256.h"
#include "sha256.h"

using namespace std;
/*-------------------------------------------------------------------
 *          Example algorithms f1, f1*, f2, f3, f4, f5, f5*
 *-------------------------------------------------------------------
 *
 *  A sample implementation of the example 3GPP authentication and
 *  key agreement functions f1, f1*, f2, f3, f4, f5 and f5*.  This is
 *  a byte-oriented implementation of the functions, and of the block
 *  cipher kernel function Rijndael.
 *
 *  This has been coded for clarity, not necessarily for efficiency.
 *
 *  The functions f2, f3, f4 and f5 share the same inputs and have 
 *  been coded together as a single function.  f1, f1* and f5* are
 *  all coded separately.
 *
 *-----------------------------------------------------------------*/

typedef unsigned char u8;


/*--------- Operator Variant Algorithm Configuration Field --------*/

            /*------- Insert your value of OP here -------*/
//u8 OP[16] = {0x63, 0xbf, 0xa5, 0x0e, 0xe6, 0x52, 0x33, 0x65,
//             0xff, 0x14, 0xc1, 0xf4, 0x5f, 0x88, 0x73, 0x7d};
            /*------- Insert your value of OP here -------*/


/*--------------------------- prototypes --------------------------*/
double time_diff(struct timeval x , struct timeval y);

void f1    ( u8 k[16], u8 rand[16], u8 sqn[6], u8 amf[2],
             u8 mac_a[8] );
void f2345 ( u8 k[16], u8 rand[16],
             u8 res[8], u8 ck[16], u8 ik[16], u8 ak[6] );
void f1star( u8 k[16], u8 rand[16], u8 sqn[6], u8 amf[2], 
             u8 mac_s[8] );
void f5star( u8 k[16], u8 rand[16],
             u8 ak[6] );
void ComputeOPc( u8 op_c[16] );
void RijndaelKeySchedule( u8 key[16] );
void RijndaelEncrypt( u8 input[16], u8 output[16] );
void print_code_mac_res();
void print_code_res_star();
void print_constant();
u8 k[16],rand_value[16],res[8],ck[16],ik[16],ak[6],mac_a[8],
sqn[6],amf[2],sqn_xor_ak[6],OP[16],op_c[16],autn[16],mac_s[8],
auts[14],retrieved_mac_a[8],retrieved_mac_s[8],sqnms_xor_ak[6],ak_star[6],sqnms[6] = {0};
bool use_opc = false;
string full_network_name;

double time_diff(struct timeval x , struct timeval y)
{
	double x_ms , y_ms , diff;
	
	x_ms = (double)x.tv_sec*1000000 + (double)x.tv_usec;
	y_ms = (double)y.tv_sec*1000000 + (double)y.tv_usec;
	
	diff = (double)y_ms - (double)x_ms;
	
	return diff;
}

/*-------------------------------------------------------------------
 *                            Algorithm f1
 *-------------------------------------------------------------------
 *
 *  Computes network authentication code MAC-A from key K, random
 *  challenge RAND, sequence number SQN and authentication management
 *  field AMF.
 *
 *-----------------------------------------------------------------*/

void f1    ( u8 k[16], u8 rand[16], u8 sqn[6], u8 amf[2], 
             u8 mac_a[8] )
{
  //u8 op_c[16]={0xE5,0xE8,0xD2,0x0F,0xB3,0x84,0xE2,0x47,0xAC,0x7A,0xA3,0xDC,0x9F,0xA3,0xDC,0xCB};
  
  //u8 op_c[16]={0x63,0xbf,0xa5,0x0e,0xe6,0x52,0x33,0x65,0xff,0x14,0xc1,0xf4,0x5f,0x88,0x73,0x7d};
  u8 temp[16];
  u8 in1[16];
  u8 out1[16];
  u8 rijndaelInput[16];
  u8 i;

  RijndaelKeySchedule( k );
  if (!use_opc){
	  ComputeOPc( op_c );
  }
  
  for (i=0; i<16; i++)
    rijndaelInput[i] = rand[i] ^ op_c[i];
  RijndaelEncrypt( rijndaelInput, temp );

  for (i=0; i<6; i++)
  {
    in1[i]    = sqn[i];
    in1[i+8]  = sqn[i];
  }
  for (i=0; i<2; i++)
  {
    in1[i+6]  = amf[i];
    in1[i+14] = amf[i];
  }

  /* XOR op_c and in1, rotate by r1=64, and XOR *
   * on the constant c1 (which is all zeroes)   */

  for (i=0; i<16; i++)
    rijndaelInput[(i+8) % 16] = in1[i] ^ op_c[i];

  /* XOR on the value temp computed before */

  for (i=0; i<16; i++)
    rijndaelInput[i] ^= temp[i];
  
  RijndaelEncrypt( rijndaelInput, out1 );
  for (i=0; i<16; i++)
    out1[i] ^= op_c[i];

  for (i=0; i<8; i++)
    mac_a[i] = out1[i];

  return;
} /* end of function f1 */


  
/*-------------------------------------------------------------------
 *                            Algorithms f2-f5
 *-------------------------------------------------------------------
 *
 *  Takes key K and random challenge RAND, and returns response RES,
 *  confidentiality key CK, integrity key IK and anonymity key AK.
 *
 *-----------------------------------------------------------------*/

void f2345 ( u8 k[16], u8 rand[16],
             u8 res[8], u8 ck[16], u8 ik[16], u8 ak[6] )
{
  //u8 op_c[16]={0xE5,0xE8,0xD2,0x0F,0xB3,0x84,0xE2,0x47,0xAC,0x7A,0xA3,0xDC,0x9F,0xA3,0xDC,0xCB};
  //u8 op_c[16]={0x63,0xbf,0xa5,0x0e,0xe6,0x52,0x33,0x65,0xff,0x14,0xc1,0xf4,0x5f,0x88,0x73,0x7d};
  //u8 op_c[16];
  u8 temp[16];
  u8 out[16];
  u8 rijndaelInput[16];
  u8 i;

  RijndaelKeySchedule( k );
  
  if (!use_opc){
	  ComputeOPc( op_c );
  }

  for (i=0; i<16; i++)
    rijndaelInput[i] = rand[i] ^ op_c[i];
  RijndaelEncrypt( rijndaelInput, temp );

  /* To obtain output block OUT2: XOR OPc and TEMP,    *
   * rotate by r2=0, and XOR on the constant c2 (which *
   * is all zeroes except that the last bit is 1).     */

  for (i=0; i<16; i++)
    rijndaelInput[i] = temp[i] ^ op_c[i];
  rijndaelInput[15] ^= 1;

  RijndaelEncrypt( rijndaelInput, out );
  for (i=0; i<16; i++)
    out[i] ^= op_c[i];

  for (i=0; i<8; i++)
    res[i] = out[i+8];
  for (i=0; i<6; i++)
    ak[i]  = out[i];

  /* To obtain output block OUT3: XOR OPc and TEMP,        *
   * rotate by r3=32, and XOR on the constant c3 (which    *
   * is all zeroes except that the next to last bit is 1). */

  for (i=0; i<16; i++)
    rijndaelInput[(i+12) % 16] = temp[i] ^ op_c[i];
  rijndaelInput[15] ^= 2;

  RijndaelEncrypt( rijndaelInput, out );
  for (i=0; i<16; i++)
    out[i] ^= op_c[i];

  for (i=0; i<16; i++)
    ck[i] = out[i];

  /* To obtain output block OUT4: XOR OPc and TEMP,         *
   * rotate by r4=64, and XOR on the constant c4 (which     *
   * is all zeroes except that the 2nd from last bit is 1). */

  for (i=0; i<16; i++)
    rijndaelInput[(i+8) % 16] = temp[i] ^ op_c[i];
  rijndaelInput[15] ^= 4;

  RijndaelEncrypt( rijndaelInput, out );
  for (i=0; i<16; i++)
    out[i] ^= op_c[i];

  for (i=0; i<16; i++)
    ik[i] = out[i];

  return;
} /* end of function f2345 */

  
/*-------------------------------------------------------------------
 *                            Algorithm f1*
 *-------------------------------------------------------------------
 *
 *  Computes resynch authentication code MAC-S from key K, random
 *  challenge RAND, sequence number SQN and authentication management
 *  field AMF.
 *
 *-----------------------------------------------------------------*/

void f1star( u8 k[16], u8 rand[16], u8 sqn[6], u8 amf[2], 
             u8 mac_s[8] )
{
  
  u8 temp[16];
  u8 in1[16];
  u8 out1[16];
  u8 rijndaelInput[16];
  u8 i;

  RijndaelKeySchedule( k );

  if (!use_opc){
	  ComputeOPc( op_c );
  }

  for (i=0; i<16; i++)
    rijndaelInput[i] = rand[i] ^ op_c[i];
  RijndaelEncrypt( rijndaelInput, temp );

  for (i=0; i<6; i++)
  {
    in1[i]    = sqn[i];
    in1[i+8]  = sqn[i];
  }
  for (i=0; i<2; i++)
  {
    in1[i+6]  = amf[i];
    in1[i+14] = amf[i];
  }

  /* XOR op_c and in1, rotate by r1=64, and XOR *
   * on the constant c1 (which is all zeroes)   */

  for (i=0; i<16; i++)
    rijndaelInput[(i+8) % 16] = in1[i] ^ op_c[i];

  /* XOR on the value temp computed before */

  for (i=0; i<16; i++)
    rijndaelInput[i] ^= temp[i];
  
  RijndaelEncrypt( rijndaelInput, out1 );
  for (i=0; i<16; i++)
    out1[i] ^= op_c[i];

  for (i=0; i<8; i++)
    mac_s[i] = out1[i+8];

  return;
} /* end of function f1star */

  
/*-------------------------------------------------------------------
 *                            Algorithm f5*
 *-------------------------------------------------------------------
 *
 *  Takes key K and random challenge RAND, and returns resynch
 *  anonymity key AK.
 *
 *-----------------------------------------------------------------*/

void f5star( u8 k[16], u8 rand[16],
             u8 ak[6] )
{
  
  u8 temp[16];
  u8 out[16];
  u8 rijndaelInput[16];
  u8 i;

  RijndaelKeySchedule( k );

  if (!use_opc){
	  ComputeOPc( op_c );
  }

  for (i=0; i<16; i++)
    rijndaelInput[i] = rand[i] ^ op_c[i];
  RijndaelEncrypt( rijndaelInput, temp );

  /* To obtain output block OUT5: XOR OPc and TEMP,         *
   * rotate by r5=96, and XOR on the constant c5 (which     *
   * is all zeroes except that the 3rd from last bit is 1). */

  for (i=0; i<16; i++)
    rijndaelInput[(i+4) % 16] = temp[i] ^ op_c[i];
  rijndaelInput[15] ^= 8;

  RijndaelEncrypt( rijndaelInput, out );
  for (i=0; i<16; i++)
    out[i] ^= op_c[i];

  for (i=0; i<6; i++)
    ak[i] = out[i];

  return;
} /* end of function f5star */

  
/*-------------------------------------------------------------------
 *  Function to compute OPc from OP and K.  Assumes key schedule has
    already been performed.
 *-----------------------------------------------------------------*/

void ComputeOPc( u8 op_c[16] )
{
  u8 i;
  
  RijndaelEncrypt( OP, op_c );
  for (i=0; i<16; i++)
    op_c[i] ^= OP[i];

  return;
} /* end of function ComputeOPc */



/*-------------------- Rijndael round subkeys ---------------------*/
u8 roundKeys[11][4][4];

/*--------------------- Rijndael S box table ----------------------*/
u8 S[256] = {
 99,124,119,123,242,107,111,197, 48,  1,103, 43,254,215,171,118,
202,130,201,125,250, 89, 71,240,173,212,162,175,156,164,114,192,
183,253,147, 38, 54, 63,247,204, 52,165,229,241,113,216, 49, 21,
  4,199, 35,195, 24,150,  5,154,  7, 18,128,226,235, 39,178,117,
  9,131, 44, 26, 27,110, 90,160, 82, 59,214,179, 41,227, 47,132,
 83,209,  0,237, 32,252,177, 91,106,203,190, 57, 74, 76, 88,207,
208,239,170,251, 67, 77, 51,133, 69,249,  2,127, 80, 60,159,168,
 81,163, 64,143,146,157, 56,245,188,182,218, 33, 16,255,243,210,
205, 12, 19,236, 95,151, 68, 23,196,167,126, 61,100, 93, 25,115,
 96,129, 79,220, 34, 42,144,136, 70,238,184, 20,222, 94, 11,219,
224, 50, 58, 10, 73,  6, 36, 92,194,211,172, 98,145,149,228,121,
231,200, 55,109,141,213, 78,169,108, 86,244,234,101,122,174,  8,
186,120, 37, 46, 28,166,180,198,232,221,116, 31, 75,189,139,138,
112, 62,181,102, 72,  3,246, 14, 97, 53, 87,185,134,193, 29,158,
225,248,152, 17,105,217,142,148,155, 30,135,233,206, 85, 40,223,
140,161,137, 13,191,230, 66,104, 65,153, 45, 15,176, 84,187, 22,
};

/*------- This array does the multiplication by x in GF(2^8) ------*/
u8 Xtime[256] = {
  0,  2,  4,  6,  8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30,
 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62,
 64, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94,
 96, 98,100,102,104,106,108,110,112,114,116,118,120,122,124,126,
128,130,132,134,136,138,140,142,144,146,148,150,152,154,156,158,
160,162,164,166,168,170,172,174,176,178,180,182,184,186,188,190,
192,194,196,198,200,202,204,206,208,210,212,214,216,218,220,222,
224,226,228,230,232,234,236,238,240,242,244,246,248,250,252,254,
 27, 25, 31, 29, 19, 17, 23, 21, 11,  9, 15, 13,  3,  1,  7,  5,
 59, 57, 63, 61, 51, 49, 55, 53, 43, 41, 47, 45, 35, 33, 39, 37,
 91, 89, 95, 93, 83, 81, 87, 85, 75, 73, 79, 77, 67, 65, 71, 69,
123,121,127,125,115,113,119,117,107,105,111,109, 99, 97,103,101,
155,153,159,157,147,145,151,149,139,137,143,141,131,129,135,133,
187,185,191,189,179,177,183,181,171,169,175,173,163,161,167,165,
219,217,223,221,211,209,215,213,203,201,207,205,195,193,199,197,
251,249,255,253,243,241,247,245,235,233,239,237,227,225,231,229
};


/*-------------------------------------------------------------------
 *  Rijndael key schedule function.  Takes 16-byte key and creates 
 *  all Rijndael's internal subkeys ready for encryption.
 *-----------------------------------------------------------------*/

void RijndaelKeySchedule( u8 key[16] )
{
  u8 roundConst;
  int i, j;

  /* first round key equals key */
  for (i=0; i<16; i++)
    roundKeys[0][i & 0x03][i>>2] = key[i];

  roundConst = 1;

  /* now calculate round keys */
  for (i=1; i<11; i++)
  {
    roundKeys[i][0][0] = S[roundKeys[i-1][1][3]]
                         ^ roundKeys[i-1][0][0] ^ roundConst;
    roundKeys[i][1][0] = S[roundKeys[i-1][2][3]]
                         ^ roundKeys[i-1][1][0];
    roundKeys[i][2][0] = S[roundKeys[i-1][3][3]]
                         ^ roundKeys[i-1][2][0];
    roundKeys[i][3][0] = S[roundKeys[i-1][0][3]]
                         ^ roundKeys[i-1][3][0];

    for (j=0; j<4; j++)
    {
      roundKeys[i][j][1] = roundKeys[i-1][j][1] ^ roundKeys[i][j][0];
      roundKeys[i][j][2] = roundKeys[i-1][j][2] ^ roundKeys[i][j][1];
      roundKeys[i][j][3] = roundKeys[i-1][j][3] ^ roundKeys[i][j][2];
    }

    /* update round constant */
    roundConst = Xtime[roundConst];
  }

  return;
} /* end of function RijndaelKeySchedule */


/* Round key addition function */
void KeyAdd(u8 state[4][4], u8 roundKeys[11][4][4], int round)
{
  int i, j;

  for (i=0; i<4; i++)
    for (j=0; j<4; j++)
      state[i][j] ^= roundKeys[round][i][j];

  return;
}


/* Byte substitution transformation */
int ByteSub(u8 state[4][4])
{
  int i, j;

  for (i=0; i<4; i++)
    for (j=0; j<4; j++)
      state[i][j] = S[state[i][j]];
  
  return 0;
}


/* Row shift transformation */
void ShiftRow(u8 state[4][4])
{
  u8 temp;

  /* left rotate row 1 by 1 */
  temp = state[1][0];
  state[1][0] = state[1][1];
  state[1][1] = state[1][2];
  state[1][2] = state[1][3];
  state[1][3] = temp;

  /* left rotate row 2 by 2 */
  temp = state[2][0];
  state[2][0] = state[2][2];
  state[2][2] = temp;
  temp = state[2][1];
  state[2][1] = state[2][3];
  state[2][3] = temp;

  /* left rotate row 3 by 3 */
  temp = state[3][0];
  state[3][0] = state[3][3];
  state[3][3] = state[3][2];
  state[3][2] = state[3][1];
  state[3][1] = temp;

  return;
}


/* MixColumn transformation*/
void MixColumn(u8 state[4][4])
{
  u8 temp, tmp, tmp0;
  int i;

  /* do one column at a time */
  for (i=0; i<4;i++)
  {
    temp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];
    tmp0 = state[0][i];

    /* Xtime array does multiply by x in GF2^8 */
    tmp = Xtime[state[0][i] ^ state[1][i]];
    state[0][i] ^= temp ^ tmp;

    tmp = Xtime[state[1][i] ^ state[2][i]];
    state[1][i] ^= temp ^ tmp;

    tmp = Xtime[state[2][i] ^ state[3][i]];
    state[2][i] ^= temp ^ tmp;

    tmp = Xtime[state[3][i] ^ tmp0];
    state[3][i] ^= temp ^ tmp;
  }

  return;
}


/*-------------------------------------------------------------------
 *  Rijndael encryption function.  Takes 16-byte input and creates 
 *  16-byte output (using round keys already derived from 16-byte 
 *  key).
 *-----------------------------------------------------------------*/

void RijndaelEncrypt( u8 input[16], u8 output[16] )
{
  u8 state[4][4];
  int i, r;

  /* initialise state array from input byte string */
  for (i=0; i<16; i++)
    state[i & 0x3][i>>2] = input[i];

  /* add first round_key */
  KeyAdd(state, roundKeys, 0);
  
  /* do lots of full rounds */
  for (r=1; r<=9; r++)
  {
    ByteSub(state);
    ShiftRow(state);
    MixColumn(state);
    KeyAdd(state, roundKeys, r);
  }

  /* final round */
  ByteSub(state);
  ShiftRow(state);
  KeyAdd(state, roundKeys, r);

  /* produce output byte string from state array */
  for (i=0; i<16; i++)
  {
    output[i] = state[i & 0x3][i>>2];
  }

  return;
} /* end of function RijndaelEncrypt */

void get_input(u8* output,int length_of_bytes, string name_of_parameter) {
	bool got_input_successfully;
	string key_input;
	do {
		got_input_successfully = true;
		cout << "please input hex value of " << name_of_parameter << "(no space allowed):";
		cin >> key_input;
		while (key_input.length()!=length_of_bytes*2||key_input.find_first_of("ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ")!=string::npos) {
			cout << "Error: the length of input string must be " << length_of_bytes*2 << " digits hex value and content must be hex digits!" << endl;
			cout << "If the secret key length is less than 32 digits, padded it by all 00" <<endl;
			cout << "please input hex value of " << name_of_parameter << "(no space allowed):";
			cin >> key_input;
		}
		char temp_hex_string[2];
		int num;
		char * endptr;
		for (int i=0;i<length_of_bytes;i++){
			temp_hex_string[0]=key_input[i*2];
			temp_hex_string[1]=key_input[i*2+1];
			temp_hex_string[2]='\0';
			num = (int)strtol(temp_hex_string, &endptr, 16);
			if (endptr==temp_hex_string){
				cout <<"error converting input into integer";
				got_input_successfully = false;
				
			}else{
			output[i]=(u8)num;
			}
		}
		
	}while (!got_input_successfully);
}

void get_input_snn(u8** snn){
        bool got_input_successfully;
        string mnc,mcc;
                got_input_successfully = true;
                cout << "please input mnc (2 or 3 decimal digits only):";
                cin >> mnc;
                while ((mnc.length()!=2 && mnc.length()!=3)||mnc.find_first_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")!=string::npos) {
                        cout << "Error: the length of input string must be 2 or 3 and content must be decimal digits!" << endl;
                        cout << "please input mnc again:";
                        cin >> mnc;
                }
                cout << "please input mcc (3 decimal digits only):";
                cin >> mcc;
                while (mcc.length()!=3||mnc.find_first_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")!=string::npos) {
                        cout << "Error: the length of input string must be 3 and content must be decimal digits!" << endl;
                        cout << "please input mcc again:";
                        cin >> mcc;
                }
		if (mnc.length()==2){
			mnc="0"+mnc;
		}
                full_network_name="5G:mnc"+mnc+".mcc"+mcc+".3gppnetwork.org";
		*snn=(u8 *)(full_network_name.c_str());
		//	printf("the value of full_network_name is:");
	        //        for (int i=0;i<32;i++){
        	//                printf("%02x",*(*snn+sizeof(u8)*i));
               // 	}
		return;
}

int main( int argc, char *argv[] )
{

		string menu_selected;
  
		cout << "######################################################################################"<<endl;
		cout << "# welcome to milenage based authentication troubleshooting tool.                     #"<<endl;
		cout << "# please input the number below to call different menu.                              #"<<endl;
		cout << "# 1. compute MAC and RES/RES* based on secret key,OP,RAND and AUTN.                  #"<<endl;
		cout << "# 2. compute MAC and RES/RES* based on secret key,OPc,RAND and AUTN.                 #"<<endl;
		cout << "# 3. print value of constant C1-C5 and R1-R5 in 3gpp 35.206 used for above item 1&2  #"<<endl;
		cout << "# 4. print the source code from 3gpp 35.206 used for above item 1&2                  #"<<endl;
		cout << "# 5. print the source code of RES* value calculation for 5G based on HMAC_SHA256     #"<<endl;
		cout << "######################################################################################"<<endl;
		cout << "Please select the menu by input number 1-5:";
		cin >> menu_selected;
		while(menu_selected!="1" && menu_selected!="2"&& menu_selected!="3" && menu_selected!="4" && menu_selected!="5"){
			cout<<"invalid input!please input number <1-5> again:";
			cin >> menu_selected;
		}
		if (menu_selected=="3"){
			//print out constant value.
			print_constant();
			return 0;
		}else if (menu_selected=="4"){
			//print out source code of mac and RES calculation.
			print_code_mac_res();
			return 0;
		}else if (menu_selected=="5"){
			//print out source code of RES* calculation.
			print_code_res_star();
			return 0;
		}else {
			get_input(k,16,"secret key(padded by 00 if less than 16 bytes)");
			
			if (menu_selected=="2"){
				use_opc = true;
				get_input(op_c,16,"opc");
			}
			else if (menu_selected=="1"){
				use_opc = false;
				get_input(OP,16,"op");
			}	
			get_input(rand_value,16,"rand");
			
			get_input(autn,16,"AUTN");
			//copy the first 6 bytes of AUTN to sqn_xor_ak.
			cout << "\nThe SQN_XOR_AK from network should be first 6 bytes of AUTN, which is (0x): ";
			for (int i=0;i<6;i++){
				sqn_xor_ak[i]=autn[i];
				printf("%02x",sqn_xor_ak[i]);
			}
			cout << "\nThe AMF from network should be the 7th and 8th byte of AUTN, which is (0x): " ;
			for (int i=0;i<2;i++){
				amf[i]=autn[i+6];
				printf("%02x",amf[i]);
			}
			cout << "\nThe MAC-A from network should be the last 8 bytes of AUTN, which is   (0x): " ;
			for (int i=0;i<8;i++){
				retrieved_mac_a[i]=autn[i+8];
				printf("%02x",retrieved_mac_a[i]);
			}
			
		
		}
        
		f2345( k, rand_value,res,ck,ik,ak);
		for (int i=0;i<6;i++){
			sqn[i]=sqn_xor_ak[i]^ak[i];
		}
		f1( k, rand_value, sqn,amf,mac_a);
		
		printf("\nBased on the above provided parameters:\n");
		if (!use_opc){
			cout << "The OPc is computed by encryption of OP value using secret key,then XOR with OP."<<endl;
		cout << "So the OPc in this case should be                            (0x):";
			for (int i=0;i<16;i++){
			printf("%02x",op_c[i]);
			}
		}
		 printf("\nThe AK computed by f2 function in 3gpp 35.206 should be      (0x):");
		for (int i=0;i<6;i++){
			printf("%02x",ak[i]);
		}
		 printf("\nThe SQN computed by AK XOR SQN_XOR_AK should be              (0x):");
		for (int i=0;i<6;i++){
			printf("%02x",sqn[i]);
		}
		cout << "\nThe CK computed by F3 function in 3gpp 35.206 should be      (0x):";
		for (int i=0;i<16;i++){
			printf("%02x",ck[i]);
		}
		cout << "\nThe IK computed by F4 function in 3gpp 35.206 should be      (0x):";
		for (int i=0;i<16;i++){
			printf("%02x",ik[i]);
		}
		cout << "\nThe RES(4G) computed by F2 function in 3gpp 35.206 should be (0x):";
		for (int i=0;i<8;i++){
			printf("%02x",res[i]);
		}
		printf("\nthe mac-a computed by f1 function in 3gpp 35.206 should be   (0x):");
		string mac_a_matched= "matched";
		for (int i=0;i<8;i++){
			printf("%02x",mac_a[i]);
			if (mac_a[i]!=retrieved_mac_a[i]){
				mac_a_matched= "not matched";
			}
		}
		cout << "\nThe MAC-A retrieved from AUTN is                             (0x):" ;
		for (int i=0;i<8;i++){
			retrieved_mac_a[i]=autn[i+8];
			printf("%02x",retrieved_mac_a[i]);
		}
			
		cout << "\n\nThe computed mac_a and retrieved mac_a from AUTN are " << mac_a_matched << endl;
		
		
		cout << endl << "\ndo you want to continue to compute RES* value for 5G auth troubleshooting?(yes/no):";
		string compute_res_star;
		cin >> compute_res_star;
		while (compute_res_star!="yes" && compute_res_star!="YES" && compute_res_star!="no" && compute_res_star!="NO"){
			cout << "input error: must be yes or no, please try again:";
			cin >> compute_res_star;
		}
        	if (compute_res_star=="yes" || compute_res_star=="YES"){
			u8 *snn;
			get_input_snn(&snn);
			u8 data_input_sha[63];
			data_input_sha[0]=0x6B;
			//copy snn to input
                        for (int i=0;i<32;i++){
                                data_input_sha[1+i]=snn[i];
                        }
			//length of SNN
			data_input_sha[33]=0x00;
			data_input_sha[34]=0x20;
			//copy rand to input.
                        for (int i=0;i<16;i++){
                                data_input_sha[35+i]=rand_value[i];
                        }
			//length of rand
			data_input_sha[51]=0x00;
			data_input_sha[52]=0x10;
			//copy RES into input.
                        for (int i=0;i<8;i++){
                                data_input_sha[53+i]=res[i];
                        }
			//length of RES
			data_input_sha[61]=0x00;
			data_input_sha[62]=0x08;
			//printf("the value of data_input_sha is:");
	                //for (int i=0;i<63;i++){
        	        //        printf("%02x",data_input_sha[i]);
                	//}
			u8 key[32];
                        for (int i=0;i<16;i++){
				key[i]=ck[i];
				key[16+i]=ik[i];
                        }

			//printf("the value of key is:");
	                //for (int i=0;i<32;i++){
        	        //        printf("%02x",key[i]);
                	//}
			u8 out[HMAC_SHA256_DIGEST_SIZE];
			hmac_sha256(out,data_input_sha,sizeof(data_input_sha),key,sizeof(key));
			cout << "\nThe RES*(5G) computed based on HMAC_SHA256 in 33.501 should be (0x):";
	                for (int i=16;i<32;i++){
        	                printf("%02x",out[i]);
                	}

		}		
		cout << endl << "\ndo you want to continue to compute the SQNms&MAC-S based on the AUTS for sync failure troubleshooting?(yes/no):";
		string compute_sqnms;
		cin >> compute_sqnms;
		while (compute_sqnms!="yes" && compute_sqnms!="YES" && compute_sqnms!="no" && compute_sqnms!="NO"){
			cout << "input error: must be yes or no, please try again:";
			cin >> compute_sqnms;
		}
        	if (compute_sqnms=="yes" || compute_sqnms=="YES"){
			cout << "Do you want to (1): calculate mac-s by input SQNms&AMF or (2): verify SQNms by input AUTS? Please input 1 or 2:";
			string one_or_two;
			cin >> one_or_two;
			while (one_or_two!="1" && one_or_two!="2"){
				cout << "input error: must be 1 or 2, please try again:";
				cin >> one_or_two;
			} 
			if (one_or_two=="2"){
				get_input(auts,14,"AUTS");
				cout << "\nThe SQNms_XOR_AK from UE should be first 6 bytes of AUTS, which is            (0x): ";
				for (int i=0;i<6;i++){
					sqnms_xor_ak[i]=auts[i];
					printf("%02x",sqnms_xor_ak[i]);
				}
				cout << "\nthe AMF from network is                                                       (0x): " ;
				for (int i=0;i<2;i++){
					printf("%02x",amf[i]);
				}
				cout << "\nthe MAC-S retrieved from message should be the last 8 bytes of AUTS, which is (0x): " ; 
				for (int i=0;i<8;i++){
					retrieved_mac_s[i]=auts[i+6];
					printf("%02x",retrieved_mac_s[i]);
				}
				f5star(k,rand_value,ak_star);
				for (int i=0;i<6;i++){
					sqnms[i]=sqnms_xor_ak[i]^ak_star[i];
				}
				cout << "\nthe AK* computed by f5* function in 3gpp 35.206 should be                     (0x): "  ;
				
				for (int i=0;i<6;i++){
					printf("%02x",ak_star[i]);
				}
				cout << "\nthe SQNms value should be AK* XOR SQNms_XOR_AK,which is                       (0x): "  ;
				for (int i=0;i<6;i++){
					printf("%02x",sqnms[i]);
				}
				f1star(k,rand_value,sqnms,amf,mac_s);
				cout << "\nthe MAC-S computed by f1* function in 3gpp 35.206 should be                   (0x): "  ;
				string mac_s_matched= "matched";
				for (int i=0;i<8;i++){
					printf("%02x",mac_s[i]);
					if (mac_s[i]!=retrieved_mac_s[i]){
						mac_s_matched= "not matched";
					}
				}
				cout << "\nthe MAC-S retrieved from message is                                           (0x): " ; 
				for (int i=0;i<8;i++){
					retrieved_mac_s[i]=auts[i+6];
					printf("%02x",retrieved_mac_s[i]);
				}
				cout << "\n\nThe computed mac_s and retrieved mac_s from AUTS are " << mac_s_matched << endl;
			}else if (one_or_two=="1"){
				get_input(sqnms,6,"SQNms");
				get_input(amf,2,"AMF");
				f1star(k,rand_value,sqnms,amf,mac_s);
				cout << "\nthe MAC-S computed by f1* function in 3gpp 35.206 should be                   (0x): "  ;
				for (int i=0;i<8;i++){
					printf("%02x",mac_s[i]);
				}
				f5star(k,rand_value,ak_star);
				cout << "\nthe AK* value should be                                                       (0x): "  ;
				for (int i=0;i<6;i++){
					printf("%02x",ak_star[i]);
				}
				for (int i=0;i<6;i++){
					sqnms_xor_ak[i]=sqnms[i]^ak_star[i];
				}
				cout << "\nthe SQNms_XOR_AK(fist 6 bytes of AUTS) value should be                        (0x): "  ;
				for (int i=0;i<6;i++){
					printf("%02x",sqnms_xor_ak[i]);
				}
				cout << endl;
			}
			
		}else{
			return 0;
		}      
        return 0;
}





void print_code_mac_res(){
	string code = R"( below source code is from Annex 3 in 3gpp 35.206:
Simulation Program Listing - Byte Oriented
/*-------------------------------------------------------------------
 *          Example algorithms f1, f1*, f2, f3, f4, f5, f5*
 *-------------------------------------------------------------------
 *
 *  A sample implementation of the example 3GPP authentication and
 *  key agreement functions f1, f1*, f2, f3, f4, f5 and f5*.  This is
 *  a byte-oriented implementation of the functions, and of the block
 *  cipher kernel function Rijndael.
 *
 *  This has been coded for clarity, not necessarily for efficiency.
 *
 *  The functions f2, f3, f4 and f5 share the same inputs and have 
 *  been coded together as a single function.  f1, f1* and f5* are
 *  all coded separately.
 *
 *-----------------------------------------------------------------*/

typedef unsigned char u8;


/*--------- Operator Variant Algorithm Configuration Field --------*/

            /*------- Insert your value of OP here -------*/
u8 OP[16] = {0x63, 0xbf, 0xa5, 0x0e, 0xe6, 0x52, 0x33, 0x65,
             0xff, 0x14, 0xc1, 0xf4, 0x5f, 0x88, 0x73, 0x7d};
            /*------- Insert your value of OP here -------*/


/*--------------------------- prototypes --------------------------*/

void f1    ( u8 k[16], u8 rand[16], u8 sqn[6], u8 amf[2],
             u8 mac_a[8] );
void f2345 ( u8 k[16], u8 rand[16],
             u8 res[8], u8 ck[16], u8 ik[16], u8 ak[6] );
void f1star( u8 k[16], u8 rand[16], u8 sqn[6], u8 amf[2], 
             u8 mac_s[8] );
void f5star( u8 k[16], u8 rand[16],
             u8 ak[6] );
void ComputeOPc( u8 op_c[16] );
void RijndaelKeySchedule( u8 key[16] );
void RijndaelEncrypt( u8 input[16], u8 output[16] );


/*-------------------------------------------------------------------
 *                            Algorithm f1
 *-------------------------------------------------------------------
 *
 *  Computes network authentication code MAC-A from key K, random
 *  challenge RAND, sequence number SQN and authentication management
 *  field AMF.
 *
 *-----------------------------------------------------------------*/

void f1    ( u8 k[16], u8 rand[16], u8 sqn[6], u8 amf[2], 
             u8 mac_a[8] )
{
  u8 op_c[16];
  u8 temp[16];
  u8 in1[16];
  u8 out1[16];
  u8 rijndaelInput[16];
  u8 i;

  RijndaelKeySchedule( k );

  ComputeOPc( op_c );

  for (i=0; i<16; i++)
    rijndaelInput[i] = rand[i] ^ op_c[i];
  RijndaelEncrypt( rijndaelInput, temp );

  for (i=0; i<6; i++)
  {
    in1[i]    = sqn[i];
    in1[i+8]  = sqn[i];
  }
  for (i=0; i<2; i++)
  {
    in1[i+6]  = amf[i];
    in1[i+14] = amf[i];
  }

  /* XOR op_c and in1, rotate by r1=64, and XOR *
   * on the constant c1 (which is all zeroes)   */

  for (i=0; i<16; i++)
    rijndaelInput[(i+8) % 16] = in1[i] ^ op_c[i];

  /* XOR on the value temp computed before */

  for (i=0; i<16; i++)
    rijndaelInput[i] ^= temp[i];
  
  RijndaelEncrypt( rijndaelInput, out1 );
  for (i=0; i<16; i++)
    out1[i] ^= op_c[i];

  for (i=0; i<8; i++)
    mac_a[i] = out1[i];

  return;
} /* end of function f1 */


  
/*-------------------------------------------------------------------
 *                            Algorithms f2-f5
 *-------------------------------------------------------------------
 *
 *  Takes key K and random challenge RAND, and returns response RES,
 *  confidentiality key CK, integrity key IK and anonymity key AK.
 *
 *-----------------------------------------------------------------*/

void f2345 ( u8 k[16], u8 rand[16],
             u8 res[8], u8 ck[16], u8 ik[16], u8 ak[6] )
{
  u8 op_c[16];
  u8 temp[16];
  u8 out[16];
  u8 rijndaelInput[16];
  u8 i;

  RijndaelKeySchedule( k );

  ComputeOPc( op_c );

  for (i=0; i<16; i++)
    rijndaelInput[i] = rand[i] ^ op_c[i];
  RijndaelEncrypt( rijndaelInput, temp );

  /* To obtain output block OUT2: XOR OPc and TEMP,    *
   * rotate by r2=0, and XOR on the constant c2 (which *
   * is all zeroes except that the last bit is 1).     */

  for (i=0; i<16; i++)
    rijndaelInput[i] = temp[i] ^ op_c[i];
  rijndaelInput[15] ^= 1;

  RijndaelEncrypt( rijndaelInput, out );
  for (i=0; i<16; i++)
    out[i] ^= op_c[i];

  for (i=0; i<8; i++)
    res[i] = out[i+8];
  for (i=0; i<6; i++)
    ak[i]  = out[i];

  /* To obtain output block OUT3: XOR OPc and TEMP,        *
   * rotate by r3=32, and XOR on the constant c3 (which    *
   * is all zeroes except that the next to last bit is 1). */

  for (i=0; i<16; i++)
    rijndaelInput[(i+12) % 16] = temp[i] ^ op_c[i];
  rijndaelInput[15] ^= 2;

  RijndaelEncrypt( rijndaelInput, out );
  for (i=0; i<16; i++)
    out[i] ^= op_c[i];

  for (i=0; i<16; i++)
    ck[i] = out[i];

  /* To obtain output block OUT4: XOR OPc and TEMP,         *
   * rotate by r4=64, and XOR on the constant c4 (which     *
   * is all zeroes except that the 2nd from last bit is 1). */

  for (i=0; i<16; i++)
    rijndaelInput[(i+8) % 16] = temp[i] ^ op_c[i];
  rijndaelInput[15] ^= 4;

  RijndaelEncrypt( rijndaelInput, out );
  for (i=0; i<16; i++)
    out[i] ^= op_c[i];

  for (i=0; i<16; i++)
    ik[i] = out[i];

  return;
} /* end of function f2345 */

  
/*-------------------------------------------------------------------
 *                            Algorithm f1*
 *-------------------------------------------------------------------
 *
 *  Computes resynch authentication code MAC-S from key K, random
 *  challenge RAND, sequence number SQN and authentication management
 *  field AMF.
 *
 *-----------------------------------------------------------------*/

void f1star( u8 k[16], u8 rand[16], u8 sqn[6], u8 amf[2], 
             u8 mac_s[8] )
{
  u8 op_c[16];
  u8 temp[16];
  u8 in1[16];
  u8 out1[16];
  u8 rijndaelInput[16];
  u8 i;

  RijndaelKeySchedule( k );

  ComputeOPc( op_c );

  for (i=0; i<16; i++)
    rijndaelInput[i] = rand[i] ^ op_c[i];
  RijndaelEncrypt( rijndaelInput, temp );

  for (i=0; i<6; i++)
  {
    in1[i]    = sqn[i];
    in1[i+8]  = sqn[i];
  }
  for (i=0; i<2; i++)
  {
    in1[i+6]  = amf[i];
    in1[i+14] = amf[i];
  }

  /* XOR op_c and in1, rotate by r1=64, and XOR *
   * on the constant c1 (which is all zeroes)   */

  for (i=0; i<16; i++)
    rijndaelInput[(i+8) % 16] = in1[i] ^ op_c[i];

  /* XOR on the value temp computed before */

  for (i=0; i<16; i++)
    rijndaelInput[i] ^= temp[i];
  
  RijndaelEncrypt( rijndaelInput, out1 );
  for (i=0; i<16; i++)
    out1[i] ^= op_c[i];

  for (i=0; i<8; i++)
    mac_s[i] = out1[i+8];

  return;
} /* end of function f1star */

  
/*-------------------------------------------------------------------
 *                            Algorithm f5*
 *-------------------------------------------------------------------
 *
 *  Takes key K and random challenge RAND, and returns resynch
 *  anonymity key AK.
 *
 *-----------------------------------------------------------------*/

void f5star( u8 k[16], u8 rand[16],
             u8 ak[6] )
{
  u8 op_c[16];
  u8 temp[16];
  u8 out[16];
  u8 rijndaelInput[16];
  u8 i;

  RijndaelKeySchedule( k );

  ComputeOPc( op_c );

  for (i=0; i<16; i++)
    rijndaelInput[i] = rand[i] ^ op_c[i];
  RijndaelEncrypt( rijndaelInput, temp );

  /* To obtain output block OUT5: XOR OPc and TEMP,         *
   * rotate by r5=96, and XOR on the constant c5 (which     *
   * is all zeroes except that the 3rd from last bit is 1). */

  for (i=0; i<16; i++)
    rijndaelInput[(i+4) % 16] = temp[i] ^ op_c[i];
  rijndaelInput[15] ^= 8;

  RijndaelEncrypt( rijndaelInput, out );
  for (i=0; i<16; i++)
    out[i] ^= op_c[i];

  for (i=0; i<6; i++)
    ak[i] = out[i];

  return;
} /* end of function f5star */

  
/*-------------------------------------------------------------------
 *  Function to compute OPc from OP and K.  Assumes key schedule has
    already been performed.
 *-----------------------------------------------------------------*/

void ComputeOPc( u8 op_c[16] )
{
  u8 i;
  
  RijndaelEncrypt( OP, op_c );
  for (i=0; i<16; i++)
    op_c[i] ^= OP[i];

  return;
} /* end of function ComputeOPc */



/*-------------------- Rijndael round subkeys ---------------------*/
u8 roundKeys[11][4][4];

/*--------------------- Rijndael S box table ----------------------*/
u8 S[256] = {
 99,124,119,123,242,107,111,197, 48,  1,103, 43,254,215,171,118,
202,130,201,125,250, 89, 71,240,173,212,162,175,156,164,114,192,
183,253,147, 38, 54, 63,247,204, 52,165,229,241,113,216, 49, 21,
  4,199, 35,195, 24,150,  5,154,  7, 18,128,226,235, 39,178,117,
  9,131, 44, 26, 27,110, 90,160, 82, 59,214,179, 41,227, 47,132,
 83,209,  0,237, 32,252,177, 91,106,203,190, 57, 74, 76, 88,207,
208,239,170,251, 67, 77, 51,133, 69,249,  2,127, 80, 60,159,168,
 81,163, 64,143,146,157, 56,245,188,182,218, 33, 16,255,243,210,
205, 12, 19,236, 95,151, 68, 23,196,167,126, 61,100, 93, 25,115,
 96,129, 79,220, 34, 42,144,136, 70,238,184, 20,222, 94, 11,219,
224, 50, 58, 10, 73,  6, 36, 92,194,211,172, 98,145,149,228,121,
231,200, 55,109,141,213, 78,169,108, 86,244,234,101,122,174,  8,
186,120, 37, 46, 28,166,180,198,232,221,116, 31, 75,189,139,138,
112, 62,181,102, 72,  3,246, 14, 97, 53, 87,185,134,193, 29,158,
225,248,152, 17,105,217,142,148,155, 30,135,233,206, 85, 40,223,
140,161,137, 13,191,230, 66,104, 65,153, 45, 15,176, 84,187, 22,
};

/*------- This array does the multiplication by x in GF(2^8) ------*/
u8 Xtime[256] = {
  0,  2,  4,  6,  8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30,
 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62,
 64, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94,
 96, 98,100,102,104,106,108,110,112,114,116,118,120,122,124,126,
128,130,132,134,136,138,140,142,144,146,148,150,152,154,156,158,
160,162,164,166,168,170,172,174,176,178,180,182,184,186,188,190,
192,194,196,198,200,202,204,206,208,210,212,214,216,218,220,222,
224,226,228,230,232,234,236,238,240,242,244,246,248,250,252,254,
 27, 25, 31, 29, 19, 17, 23, 21, 11,  9, 15, 13,  3,  1,  7,  5,
 59, 57, 63, 61, 51, 49, 55, 53, 43, 41, 47, 45, 35, 33, 39, 37,
 91, 89, 95, 93, 83, 81, 87, 85, 75, 73, 79, 77, 67, 65, 71, 69,
123,121,127,125,115,113,119,117,107,105,111,109, 99, 97,103,101,
155,153,159,157,147,145,151,149,139,137,143,141,131,129,135,133,
187,185,191,189,179,177,183,181,171,169,175,173,163,161,167,165,
219,217,223,221,211,209,215,213,203,201,207,205,195,193,199,197,
251,249,255,253,243,241,247,245,235,233,239,237,227,225,231,229
};


/*-------------------------------------------------------------------
 *  Rijndael key schedule function.  Takes 16-byte key and creates 
 *  all Rijndael's internal subkeys ready for encryption.
 *-----------------------------------------------------------------*/

void RijndaelKeySchedule( u8 key[16] )
{
  u8 roundConst;
  int i, j;

  /* first round key equals key */
  for (i=0; i<16; i++)
    roundKeys[0][i & 0x03][i>>2] = key[i];

  roundConst = 1;

  /* now calculate round keys */
  for (i=1; i<11; i++)
  {
    roundKeys[i][0][0] = S[roundKeys[i-1][1][3]]
                         ^ roundKeys[i-1][0][0] ^ roundConst;
    roundKeys[i][1][0] = S[roundKeys[i-1][2][3]]
                         ^ roundKeys[i-1][1][0];
    roundKeys[i][2][0] = S[roundKeys[i-1][3][3]]
                         ^ roundKeys[i-1][2][0];
    roundKeys[i][3][0] = S[roundKeys[i-1][0][3]]
                         ^ roundKeys[i-1][3][0];

    for (j=0; j<4; j++)
    {
      roundKeys[i][j][1] = roundKeys[i-1][j][1] ^ roundKeys[i][j][0];
      roundKeys[i][j][2] = roundKeys[i-1][j][2] ^ roundKeys[i][j][1];
      roundKeys[i][j][3] = roundKeys[i-1][j][3] ^ roundKeys[i][j][2];
    }

    /* update round constant */
    roundConst = Xtime[roundConst];
  }

  return;
} /* end of function RijndaelKeySchedule */


/* Round key addition function */
void KeyAdd(u8 state[4][4], u8 roundKeys[11][4][4], int round)
{
  int i, j;

  for (i=0; i<4; i++)
    for (j=0; j<4; j++)
      state[i][j] ^= roundKeys[round][i][j];

  return;
}


/* Byte substitution transformation */
int ByteSub(u8 state[4][4])
{
  int i, j;

  for (i=0; i<4; i++)
    for (j=0; j<4; j++)
      state[i][j] = S[state[i][j]];
  
  return 0;
}


/* Row shift transformation */
void ShiftRow(u8 state[4][4])
{
  u8 temp;

  /* left rotate row 1 by 1 */
  temp = state[1][0];
  state[1][0] = state[1][1];
  state[1][1] = state[1][2];
  state[1][2] = state[1][3];
  state[1][3] = temp;

  /* left rotate row 2 by 2 */
  temp = state[2][0];
  state[2][0] = state[2][2];
  state[2][2] = temp;
  temp = state[2][1];
  state[2][1] = state[2][3];
  state[2][3] = temp;

  /* left rotate row 3 by 3 */
  temp = state[3][0];
  state[3][0] = state[3][3];
  state[3][3] = state[3][2];
  state[3][2] = state[3][1];
  state[3][1] = temp;

  return;
}


/* MixColumn transformation*/
void MixColumn(u8 state[4][4])
{
  u8 temp, tmp, tmp0;
  int i;

  /* do one column at a time */
  for (i=0; i<4;i++)
  {
    temp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];
    tmp0 = state[0][i];

    /* Xtime array does multiply by x in GF2^8 */
    tmp = Xtime[state[0][i] ^ state[1][i]];
    state[0][i] ^= temp ^ tmp;

    tmp = Xtime[state[1][i] ^ state[2][i]];
    state[1][i] ^= temp ^ tmp;

    tmp = Xtime[state[2][i] ^ state[3][i]];
    state[2][i] ^= temp ^ tmp;

    tmp = Xtime[state[3][i] ^ tmp0];
    state[3][i] ^= temp ^ tmp;
  }

  return;
}


/*-------------------------------------------------------------------
 *  Rijndael encryption function.  Takes 16-byte input and creates 
 *  16-byte output (using round keys already derived from 16-byte 
 *  key).
 *-----------------------------------------------------------------*/

void RijndaelEncrypt( u8 input[16], u8 output[16] )
{
  u8 state[4][4];
  int i, r;

  /* initialise state array from input byte string */
  for (i=0; i<16; i++)
    state[i & 0x3][i>>2] = input[i];

  /* add first round_key */
  KeyAdd(state, roundKeys, 0);
  
  /* do lots of full rounds */
  for (r=1; r<=9; r++)
  {
    ByteSub(state);
    ShiftRow(state);
    MixColumn(state);
    KeyAdd(state, roundKeys, r);
  }

  /* final round */
  ByteSub(state);
  ShiftRow(state);
  KeyAdd(state, roundKeys, r);

  /* produce output byte string from state array */
  for (i=0; i<16; i++)
  {
    output[i] = state[i & 0x3][i>>2];
  }

  return;
} /* end of function RijndaelEncrypt */ )";
	cout << code << endl;
	return;
}

void print_code_res_star(){
	string code=R"(
/* below hmac_sha256 source code is from https://github.com/aperezdc/hmac-sha256 */

void
sha256_init(sha256_t *p)
{
  p->state[0] = 0x6a09e667;
  p->state[1] = 0xbb67ae85;
  p->state[2] = 0x3c6ef372;
  p->state[3] = 0xa54ff53a;
  p->state[4] = 0x510e527f;
  p->state[5] = 0x9b05688c;
  p->state[6] = 0x1f83d9ab;
  p->state[7] = 0x5be0cd19;
  p->count = 0;
}

#define S0(x) (ROTR32(x, 2) ^ ROTR32(x,13) ^ ROTR32(x, 22))
#define S1(x) (ROTR32(x, 6) ^ ROTR32(x,11) ^ ROTR32(x, 25))
#define s0(x) (ROTR32(x, 7) ^ ROTR32(x,18) ^ (x >> 3))
#define s1(x) (ROTR32(x,17) ^ ROTR32(x,19) ^ (x >> 10))

#define blk0(i) (W[i] = data[i])
#define blk2(i) (W[i&15] += s1(W[(i-2)&15]) + W[(i-7)&15] + s0(W[(i-15)&15]))

#define Ch(x,y,z) (z^(x&(y^z)))
#define Maj(x,y,z) ((x&y)|(z&(x|y)))

#define a(i) T[(0-(i))&7]
#define b(i) T[(1-(i))&7]
#define c(i) T[(2-(i))&7]
#define d(i) T[(3-(i))&7]
#define e(i) T[(4-(i))&7]
#define f(i) T[(5-(i))&7]
#define g(i) T[(6-(i))&7]
#define h(i) T[(7-(i))&7]



#define R(a,b,c,d,e,f,g,h, i) h += S1(e) + Ch(e,f,g) + K[i+j] + (j?blk2(i):blk0(i));\
  d += h; h += S0(a) + Maj(a, b, c)

#define RX_8(i) \
  R(a,b,c,d,e,f,g,h, i); \
  R(h,a,b,c,d,e,f,g, (i+1)); \
  R(g,h,a,b,c,d,e,f, (i+2)); \
  R(f,g,h,a,b,c,d,e, (i+3)); \
  R(e,f,g,h,a,b,c,d, (i+4)); \
  R(d,e,f,g,h,a,b,c, (i+5)); \
  R(c,d,e,f,g,h,a,b, (i+6)); \
  R(b,c,d,e,f,g,h,a, (i+7))


static const uint32_t K[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void
sha256_transform(uint32_t *state, const uint32_t *data)
{
  uint32_t W[16];
  unsigned j;
  
  uint32_t a,b,c,d,e,f,g,h;
  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];
  f = state[5];
  g = state[6];
  h = state[7];
  
  for (j = 0; j < 64; j += 16)
  {
   
    RX_8(0); RX_8(8);
    
  }

  
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
  
}

#undef S0
#undef S1
#undef s0
#undef s1

static void
sha256_write_byte_block(sha256_t *p)
{
  uint32_t data32[16];
  unsigned i;
  for (i = 0; i < 16; i++)
    data32[i] =
      ((uint32_t)(p->buffer[i * 4    ]) << 24) +
      ((uint32_t)(p->buffer[i * 4 + 1]) << 16) +
      ((uint32_t)(p->buffer[i * 4 + 2]) <<  8) +
      ((uint32_t)(p->buffer[i * 4 + 3]));
  sha256_transform(p->state, data32);
}


void
sha256_hash(unsigned char *buf, const unsigned char *data, size_t size)
{
  sha256_t hash;
  sha256_init(&hash);
  sha256_update(&hash, data, size);
  sha256_final(&hash, buf);
}


void
sha256_update(sha256_t *p, const unsigned char *data, size_t size)
{
  uint32_t curBufferPos = (uint32_t)p->count & 0x3F;
  while (size > 0)
  {
    p->buffer[curBufferPos++] = *data++;
    p->count++;
    size--;
    if (curBufferPos == 64)
    {
      curBufferPos = 0;
      sha256_write_byte_block(p);
    }
  }
}


void
sha256_final(sha256_t *p, unsigned char *digest)
{
  uint64_t lenInBits = (p->count << 3);
  uint32_t curBufferPos = (uint32_t)p->count & 0x3F;
  unsigned i;
  p->buffer[curBufferPos++] = 0x80;
  while (curBufferPos != (64 - 8))
  {
    curBufferPos &= 0x3F;
    if (curBufferPos == 0)
      sha256_write_byte_block(p);
    p->buffer[curBufferPos++] = 0;
  }
  for (i = 0; i < 8; i++)
  {
    p->buffer[curBufferPos++] = (unsigned char)(lenInBits >> 56);
    lenInBits <<= 8;
  }
  sha256_write_byte_block(p);

  for (i = 0; i < 8; i++)
  {
    *digest++ = (unsigned char)(p->state[i] >> 24);
    *digest++ = (unsigned char)(p->state[i] >> 16);
    *digest++ = (unsigned char)(p->state[i] >> 8);
    *digest++ = (unsigned char)(p->state[i]);
  }
  sha256_init(p);
}



/*
 * HMAC(H, K) == H(K ^ opad, H(K ^ ipad, text))
 *
 *    H: Hash function (sha256)
 *    K: Secret key
 *    B: Block byte length
 *    L: Byte length of hash function output
 *
 * https://tools.ietf.org/html/rfc2104
 */

#define B 64
#define L (SHA256_DIGEST_SIZE)
#define K (SHA256_DIGEST_SIZE * 2)

#define I_PAD 0x36
#define O_PAD 0x5C

void
hmac_sha256 (uint8_t out[HMAC_SHA256_DIGEST_SIZE],
             const uint8_t *data, size_t data_len,
             const uint8_t *key, size_t key_len)
{
{

    sha256_t ss;
    uint8_t kh[SHA256_DIGEST_SIZE];

    /*
     * If the key length is bigger than the buffer size B, apply the hash
     * function to it first and use the result instead.
     */
    if (key_len > B) {
        sha256_init (&ss);
        sha256_update (&ss, key, key_len);
        sha256_final (&ss, kh);
        key_len = SHA256_DIGEST_SIZE;
        key = kh;
    }

    /*
     * (1) append zeros to the end of K to create a B byte string
     *     (e.g., if K is of length 20 bytes and B=64, then K will be
     *     appended with 44 zero bytes 0x00)
     * (2) XOR (bitwise exclusive-OR) the B byte string computed in step
     *     (1) with ipad
     */
    uint8_t kx[B];
    for (size_t i = 0; i < key_len; i++) kx[i] = I_PAD ^ key[i];
    for (size_t i = key_len; i < B; i++) kx[i] = I_PAD ^ 0;

    /*
     * (3) append the stream of data 'text' to the B byte string resulting
     *     from step (2)
     * (4) apply H to the stream generated in step (3)
     */
    sha256_init (&ss);
    sha256_update (&ss, kx, B);
    sha256_update (&ss, data, data_len);
    sha256_final (&ss, out);

    /*
     * (5) XOR (bitwise exclusive-OR) the B byte string computed in
     *     step (1) with opad
     *
     * NOTE: The kx variable is reused.
     */
    for (size_t i = 0; i < key_len; i++) kx[i] = O_PAD ^ key[i];
    for (size_t i = key_len; i < B; i++) kx[i] = O_PAD ^ 0;

    /*
     * (6) append the H result from step (4) to the B byte string
     *     resulting from step (5)
     * (7) apply H to the stream generated in step (6) and output
     *     the result
     */
    sha256_init (&ss);
    sha256_update (&ss, kx, B);
    sha256_update (&ss, out, SHA256_DIGEST_SIZE);
    sha256_final (&ss, out);
}
)";
	cout << code <<endl;
	return;
}
void print_constant(){
	string contantvalue=R"(The C1-C5 and R1-R5 used in this program is from 3gpp 35.206, and the values are as below:
	c1: 0x00000000000000000000000000000000
	c2: 0x00000000000000000000000000000001
	c3: 0x00000000000000000000000000000002
	c4: 0x00000000000000000000000000000004
	c5: 0x00000000000000000000000000000008
	R1: 64
	R2: 0
	R3: 32
	R4: 64
	R5: 96
	)";
	cout << contantvalue<<endl;
	return;
}
 

