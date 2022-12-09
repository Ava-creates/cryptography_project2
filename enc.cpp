#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>

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
LweSample* encrypt16(int16_t plaintext) {
    LweSample* ciphertext = new_gate_bootstrapping_ciphertext_array(16, params);
    for (int i=0; i<16; i++) {
        bootsSymEncrypt(&ciphertext[i], (plaintext>>i)&1, key);
    }
    delete_gate_bootstrapping_ciphertext_array(16, ciphertext);
}

void export_ciphertext(LweSample* &ciphertext) {
    //export the 2x16 ciphertexts to a file (for the cloud)
    FILE* cloud_data = fopen("cloud.data","wb");
    for (int i=0; i<16; i++) {
        export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext[i], params);
    }
    fclose(cloud_data);

}


int main() {
    generate_keys(110);
    char string_of_bits = '110010101010101001010111100101001010111010101101';
    int buffer = string_of_bits.length();
    int string_index = 0;
    if (buffer - string_index >= 16) {
        //encrypt next 16 bits
        export_ciphertext(encrypt16(int16_t(string_of_bits[string_index:string_index+16])));
        string_index = string_index + 16
    }
    else if (buffer - string_index < 16){
        //encrypt remaining bits
        export_ciphertext(encrypt16(int16_t(string_of_bits[string_index:buffer])));
    }
}