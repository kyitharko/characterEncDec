#include <stdio.h>
#include <iostream>
#include <string>
#include <cstring>
#include "base64.hpp"
#include "new_peks.hpp"
using namespace std;

int main()
{
   peksOpt p_opt;
   pairing_t pairing;
   pbc_param_t param;
   int len;

   element_t H1_W2;
   p_opt.init_pbc_param_pairing(param, pairing);
   double P = mpz_get_d(pairing->r);
   int nlogP = log2(P);
   p_opt.KeyGen(param, pairing);

   char A[] = "hi";
   std::string str_test = "hi";
   char *W2 = &A[0];
   const char *W1 = str_test.c_str();
   int lenW2 = (int)strlen(W2);

   //std::pair<element_t, char*> peks;
   char *hashedW2 = (char*)malloc(sizeof(char)*SHA512_DIGEST_LENGTH*2+1);
   p_opt.sha512(W2, lenW2, hashedW2);
   element_init_G1(H1_W2, pairing);
   element_from_hash(H1_W2, hashedW2, strlen(hashedW2));
   //element_printf("H1_W2 %B\n", H1_W2);

   /* PEKS(key_pub, W2) */
   p_opt.set_B((char*)malloc(sizeof(char)*(nlogP)));
   p_opt.PEKS(p_opt.getPubg(), p_opt.getPubh(), &pairing, &H1_W2, nlogP);
   element_t* peks;

   char* B;
   peks = p_opt.getPEKS();
   B = p_opt.getB();
   //p_opt.key_printf();

   std::cout << "the original B value is >>>> " << std::endl << "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n";
   for(int i = 0; i <= nlogP; i++)
      printf("%c", B[i]);
   printf("\n");
   std::cout << "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n";

   element_t* tw;
   element_t H1_W1;
   /* H1(W) */
   char *hashedW = (char*)malloc(sizeof(char)*SHA512_DIGEST_LENGTH*2+1);
   p_opt.sha512(W1, (int)strlen(W1), hashedW);
   element_init_G1(H1_W1, pairing);
   element_from_hash(H1_W1, hashedW, (int)strlen(hashedW));
   p_opt.Trapdoor(&pairing, p_opt.getPriKey(), &H1_W1);
   tw = p_opt.getTw();
   int match = p_opt.Test(p_opt.getPubg(), p_opt.getPubh(), peks, B, tw, pairing);
   if(match)
     printf("Equal\n");
   else
     printf("Not equal\n");


   len = element_length_in_bytes(*p_opt.getPubg());
   unsigned char g_data[len];
   element_to_bytes(g_data, *p_opt.getPubg());
   std::string g_encoded = base64_encode(g_data, len);

   len = element_length_in_bytes(*p_opt.getPubh());
   unsigned char h_data [len];
   element_to_bytes(h_data, *p_opt.getPubh());
   std::string h_encoded = base64_encode(h_data, len);


   std::string g_decoded = base64_decode(g_encoded);
   std::string h_decoded = base64_decode(h_encoded);


   unsigned char* g_array = (unsigned char*)g_decoded.c_str();
   unsigned char* h_array = (unsigned char*)h_decoded.c_str();

   element_t new_g;
   element_t new_h;

   element_init_G1(new_g, pairing);
   element_init_G1(new_h, pairing);

   element_from_bytes(new_g, g_array);
   element_from_bytes(new_h, h_array);

   p_opt.setPubKey(&new_g, &new_h);


   //start to encode the peks
   len = element_length_in_bytes(*peks);
   unsigned char peks_data[len];
   element_to_bytes(peks_data, *peks);
   std::string peks_encoded = base64_encode(peks_data, len);

   //start to encode Hr
   std::string h_string(B);
   std::string hr_string = GetHexFromBin(h_string);
   //output of encoded values
   std::cout << "peks_encoded is " << peks_encoded << std::endl;
   std::cout << "hr_string_encoded is " << hr_string << std::endl;

   //start to decode peks
   std::string new_peks_decoded = base64_decode(peks_encoded);
   unsigned char* new_peks_array = (unsigned char*)new_peks_decoded.c_str();

   //creation of new peks
   element_t new_peks;
   element_init_G1(new_peks, pairing);
   element_from_bytes(new_peks, new_peks_array);
   p_opt.set_peks(new_peks);

   //creation of new hr
   std::string hr_string_Bin_arr = GetBinFromHex(hr_string);
   char *new_B = (char*)hr_string_Bin_arr.c_str();
   std::cout << "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n";
   for(int i = 0; i < nlogP; i++)
      printf("%c", new_B[i]);
   printf("\n");
   std::cout << "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n";
   p_opt.set_B(new_B);

//   peks = p_opt.getPEKS();
//   B = p_opt.getB();


   int count = 0;

   for(int j = 0; j <1; j++)
   {
      match = p_opt.Test(p_opt.getPubg(), p_opt.getPubh(), &new_peks, new_B, tw, pairing);

      if(match)
      {
        count++;
      }
   }

   std::cout << "equal count is >>> " << count << std::endl;

   element_to_bytes(g_data, *p_opt.getPubg());
   g_encoded = base64_encode(g_data, len);

   element_to_bytes(h_data, *p_opt.getPubh());
   h_encoded = base64_encode(h_data, len);


   string s = "Hello";
   unsigned char const* sByte = (unsigned char const*)s.c_str();
   len = (int)strlen((const char*)sByte);
   string enc = base64_encode(sByte, len);
   std::cout << "enc is " << enc << std::endl;
   string dec = base64_decode(enc);
   std::cout << "dec is " << dec << std::endl;

   return 0;

}
