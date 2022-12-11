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
represented in 8 bits when converted to ASCII, and the library we used encrypted 16 
bits at a time, so for every call to the encryption algorithm
The organization of the code follows this general format:
    
TO ENCRYPT & STORE PLAINTEXT: [key generation -> store secret & cloud keys in secret.key & cloud.key, respectively -> input plaintext string to array of 16-bit integers -> encrypt 16-bit integer -> add 16 ciphertext bits to cloud.data file -> repeat until all bits are exported into cloud.data]

TO ENCRYPT & STORE QUERY STRING: [input plaintext string to array of 16-bit integers -> encrypt 16-bit integer (with same keys as above) -> add 16 ciphertext bits to query.data file -> repeat until all bits are exported into query.data]

KEY RETRIEVAL: [read from secure files secret.key & cloud.key -> store in variables key & bk, respectively]

STRING COMPARISON: [pass ciphertext read from cloud.data & encrypted query string from query.data into compare strings function, along with cloud key -> returns integer final answer (how many times query string appears in plaintext -> encrypt final answer before returning]

DERIVATION OF FINAL ANSWER: [encrypted final answer passed into decrypt method with scret key, returns final answer as an integer]

***Due to difficulties encountered installing and using the library, we were unable to test our code as a whole, and unable to produce code that compiles without extensive setup and installation. Our code is thouroughly commented for legibility to provide some more clarification as to what each section does.


    WORKS CITED
@misc{TFHE,
Title   = {{TFHE}: Fast Fully Homomorphic Encryption Library},
Author  = {Ilaria Chillotti and  Nicolas Gama and Mariya Georgieva and Malika Izabach{\`e}ne},
Note    = {https://tfhe.github.io/tfhe/},
Year    = {August 2016}
}
