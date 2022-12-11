# Cryptography Project 2 - Type 3
## Computation Over Outsourced Encrypted Data via Homomorphic Encryption
### By: Avani Tiwari, Jonathan Guan, Jeffrey Rathgeber

    GENERAL INFO
The goal of our project is to allow for the querying of a function over 
externally-stored encrypted data, without the need for decryption of the data 
itself. This ensures that user data is secure from any malicious actor with access 
to where the data is stored, during the entire process of computation, and allows 
for data to be put to use while maintaining security and integrity. The particular
query function chosen allows a user to pass a string into a function that would
then parse the ciphertext and return the integer amount of times the query string
appeared in the ciphertext, without reverting it back to palintext at any time.

    OUR PROGRESS
The team was able to put together a coherent body of code using several user-defined 
functions written by both us and from the library cited below. Characters can be 
represented in 8 bits when converted to ASCII, and the library we used encrypted 16 bits at a time, so for every call to the encryption algorithm
The organization of the
code follows this general format:
    
TO ENCRYPT & STORE PLAINTEXT: [key generation -> input plaintext string to array of 16-bit integers -> encrypt 16-bit integer -> add 16 ciphertext bits to cloud.data file]
    


    WORKS CITED
@misc{TFHE,
Title   = {{TFHE}: Fast Fully Homomorphic Encryption Library},
Author  = {Ilaria Chillotti and  Nicolas Gama and Mariya Georgieva and Malika Izabach{\`e}ne},
Note    = {https://tfhe.github.io/tfhe/},
Year    = {August 2016}
}
