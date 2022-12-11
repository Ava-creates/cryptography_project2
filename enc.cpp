#include "tfhe.h"
#include "tfhe_io.h"
#include <stdio.h>
#include <string>
#include <iostream>
using namespace std;

// generate cloud keys and put them in appropriate files, will use same key for every 16 bits to encrypt
void generate_keys(const int minimum_lambda) {
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    //generate a random key
    uint32_t seed[] = { 314, 1592, 657 };
    tfhe_random_generator_setSeed(seed,3);
    TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);

    //export the secret key to file for later use
    FILE* secret_key = fopen("secret.key","wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
    fclose(secret_key);

    //export the cloud key to a file (for the cloud)
    FILE* cloud_key = fopen("cloud.key","wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);

    //clean up all pointers
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

}

//encrypt the 16 bits of input
LweSample* encrypt16(int16_t plaintext, TFheGateBootstrappingParameterSet* params, TFheGateBootstrappingSecretKeySet* key) {
    LweSample* ciphertext = new_gate_bootstrapping_ciphertext_array(16, params);
    for (int i=0; i<16; i++) {
        bootsSymEncrypt(&ciphertext[i], (plaintext>>i)&1, key);
    }
    // delete_gate_bootstrapping_ciphertext_array(16, ciphertext);
    return ciphertext;
}

void export_ciphertext(LweSample* &ciphertext, TFheGateBootstrappingParameterSet* params) {
    //export the 2x16 ciphertexts to a file (for the cloud)
    FILE* cloud_data = fopen("cloud.data","wb");
    for (int i=0; i<16; i++) {
        export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext[i], params);
    }
    fclose(cloud_data);

}

// it does performs the AND  operations till the result is in a single bit
//input : xnor lwesample array c , cloudkey set - output - one bit lwesample , length of the lwesample array 
LweSample* end ( int l,  const LweSample* c, const TFheGateBootstrappingCloudKeySet* bk)
{

    //int l= sizeof(c)/sizeof(c[0]);


    LweSample* resul[ l ]; 
    LweSample* r= new_gate_bootstrapping_ciphertext(bk->params);  //uh not sure how to make it one variable 

    for (int i =0; i<l-1; i+=2)

        {
        
            // # "And" the current bit and the next bit, and add the result
            // # to the resulting string
            bootsAND(r, &c[i], &c[i+1], bk);
            resul[i]=r;
        
        }
        
    while( l>1){
        
        for (int i =0; i<l-1; i+=2)

        {
        
            // # "And" the current bit and the next bit, and add the result
            // # to the resulting string
            bootsAND(r, &c[i], &c[i+1], bk);
            resul[i]=r;
        
        }
        
        l=l/2;
        
    }


    return resul[0];

}

// input - encrypted string ( not a sentence )+ encrypted query word  (lwesample array pointers) , length of encrypted query word (int) , cloudkeyset
//output - one bit lwesample 
//compares two strings and returns the lwesample bit (0 ==false && 1==true)
LweSample* compare_strings( const LweSample* a, const LweSample* b, int n, const TFheGateBootstrappingCloudKeySet* bk)
{ 
    int len = sizeof(a)/sizeof(a[0]);
    LweSample* t= new_gate_bootstrapping_ciphertext(bk->params);
    bootsCONSTANT(t, 0, bk);
    LweSample* resul[ len ]; 

    if(len != n)
    {
        resul[0]=t;
        cout << resul[0];
    }

    LweSample* tmps = new_gate_bootstrapping_ciphertext_array(n, bk->params);   

    // not sure what exactly the above thing gives but hopefully an array of len equal to n 

    for (int i =0; i< n; i++)
        {
            bootsXNOR(&tmps[i], &a[i], &b[i], bk); 
            //    # the xnor to check equality   for every bit and storing the result in     tmps  
           
        }

    // LweSample* result = new_gate_bootstrapping_ciphertext_array(n-1, bk->params);   
    return end(result, tmps, bk);

}
//// du duh duh 



int main() {
    generate_keys(110);
    string string_of_bits = "110010101010101001010111100101001010111010101101";
    int buffer = string_of_bits.length();
    int string_index = 0;

    FILE* secret_key = fopen("secret.key","rb");
    FILE* cloud_key = fopen("cloud.key","rb");
    FILE* cloud_data = fopen("cloud.data","rb");

    while (0==0) {
        if (buffer - string_index >= 16) {
            //encrypt next 16 bits
            export_ciphertext(encrypt16(int16_t(string_of_bits[string_index:string_index+16]), ));
            string_index = string_index + 16
        }
        else if (buffer - string_index < 16){
            //encrypt remaining bits
            export_ciphertext(encrypt16(int16_t(string_of_bits[string_index:buffer])));
            break;
        }
    }
}
