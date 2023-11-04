/* * */



#define SHA3_256_DIGEST_LEN 32
#define SHA3_512_DIGEST_LEN 64
#define SHA3_256_BLOCK_LEN 136
#define SHA3_512_BLOCK_LEN 72
#define SHA3_256_B64_LEN      43
#define SHA3_512_B64_LEN      86
#define SHA3_256_DIGEST_STR_LEN   (SHA3_256_DIGEST_LEN * 2 + 1)
#define SHA3_512_DIGEST_STR_LEN   (SHA3_512_DIGEST_LEN * 2 + 1)

void Keccak(unsigned int rate, unsigned int capacity, const unsigned char *input, unsigned long long int inputByteLen, unsigned char delimitedSuffix, unsigned char *output, unsigned long long int outputByteLen);

/* * */

/* * */

/* * */

/* * */
void FIPS202_SHA3_256(const unsigned char *input, unsigned int inputByteLen, unsigned char *output);

/* * */

/* * */
void FIPS202_SHA3_512(const unsigned char *input, unsigned int inputByteLen, unsigned char *output);
