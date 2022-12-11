#include <stdio.h>
#include <string>
#include <vector>
#include <stack>
#include <string>
#include <iostream>
#include <fstream>
#include "tfhe.h"
#include "tfhe_io.h"

// using namespace std;

int16_t decrypt(LweSample* answer, TFheGateBootstrappingSecretKeySet* key) {
    int16_t int_answer = 0;
    for (int i=0; i<16; i++) {
        int ai = bootsSymDecrypt(&answer[i], key);
        int_answer |= (ai<<i);
    }
    return int_answer;
}

std::vector<int16_t> string_to_bitarray(const std::string& s) {
	int n = s.size();
	std::vector<int16_t> binarystr;
	std::stack<int16_t> reverse;
	for (int i = n - 1; i >= 0; i--) {
		if ((n - i) % 2 == 1) {
			reverse.push((int16_t)s[i]);	//Every other character, push onto the stack
		}
		else {
			int16_t temp = reverse.top();
			std::cout << ((int16_t)s[i] << 8) << " ";
			reverse.pop();                              //Every other character, add the character shifted 1 char size (8bits)
			reverse.push(((int16_t)s[i] << 8) + (int16_t)temp);    //left to the existing value on the stack
		}

	}
	while (!reverse.empty()) {
		binarystr.push_back(reverse.top());	//Reverse the order
		reverse.pop();
	}
	return binarystr;
}

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

// creates empty ciphertext array to be updated by encrypt16()
LweSample* init_ciphertext_array(const TFheGateBootstrappingParameterSet* params) {
    LweSample* initCipher = new_gate_bootstrapping_ciphertext_array(16, params);
    return initCipher;
}

//encrypt the 16 bits of input
LweSample* encrypt16(int16_t plaintext, LweSample* ciphertext, const TFheGateBootstrappingSecretKeySet* key) {
    for (int i=0; i<16; i++) {
        bootsSymEncrypt(&ciphertext[i], (plaintext>>i)&1, key);
    }
    return ciphertext;
}

void export_ciphertext(LweSample* ciphertext, const TFheGateBootstrappingParameterSet* params) {
    FILE* cloud_data = fopen("cloud.data","wb");
    for (int i=0; i<16; i++) {
        export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext[i], params);
    }
    fclose(cloud_data);
}


int main() {

    /*
    TEST STRING INPUT S
    */
    const std::string s = "This is my test string.";


    const int minimum_lambda = 110;
    generate_keys(minimum_lambda);

    std::vector<int16_t> bitarray = string_to_bitarray(s);
    int buffer = sizeof(bitarray);

    FILE* secret_key = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

    FILE* cloud_key = fopen("cloud.key","rb");
    TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);

    const TFheGateBootstrappingParameterSet* params = key->params;
    LweSample* initial_ciphertext = init_ciphertext_array(params);

    for (int i=0; i<buffer; i++) {
        export_ciphertext(encrypt16(bitarray[i], initial_ciphertext, key), params);
    }

    // LweSample* cipher = new_gate_bootstrapping_ciphertext_array(16, key->params);
    // FILE* cloud_data = fopen("cloud.data","rb");
    // for (int i=0; i<16; i++) 
    //     import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &cipher[i], params);
    // fclose(cloud_data);

    //decrypt answer.data file
    LweSample* answer = new_gate_bootstrapping_ciphertext_array(16, params);
    FILE* answer_data = fopen("answer.data","rb");
    for (int i=0; i<(16*buffer); i++) {
        import_gate_bootstrapping_ciphertext_fromFile(answer_data, &answer[i], params);
    }
    fclose(answer_data);
    int final_answer = decrypt(answer, key);
}
