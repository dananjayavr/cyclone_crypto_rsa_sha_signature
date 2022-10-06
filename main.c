#include <stdio.h>
#include <sys/random.h>
#include "core/crypto.h"
#include "pkc/rsa.h"
#include "rng/yarrow.h"
#include "pkix/pem_import.h"

#define USE_CYCLONE_KEYS 0
#define USE_OPENSSL_KEYS 1

// PRNG context
YarrowContext yarrowContext;

// This is the message to be signed.
unsigned char message[] = {0xF4, 0x5D, 0x55, 0xF3, 0x55, 0x51, 0xE9, 0x75, 0xD6, 0xA8, 0xDC, 0x7E, 0xA9, 0xF4, 0x88, 0x59,
                           0x39, 0x40, 0xCC, 0x75, 0x69, 0x4A, 0x27, 0x8F, 0x27, 0xE5, 0x78, 0xA1, 0x63, 0xD8, 0x39, 0xB3,
                           0x40, 0x40, 0x84, 0x18, 0x08, 0xCF, 0x9C, 0x58, 0xC9, 0xB8, 0x72, 0x8B, 0xF5, 0xF9, 0xCE, 0x8E,
                           0xE8, 0x11, 0xEA, 0x91, 0x71, 0x4F, 0x47, 0xBA, 0xB9, 0x2D, 0x0F, 0x6D, 0x5A, 0x26, 0xFC, 0xFE,
                           0xEA, 0x6C, 0xD9, 0x3B, 0x91, 0x0C, 0x0A, 0x2C, 0x96, 0x3E, 0x64, 0xEB, 0x18, 0x23, 0xF1, 0x02,
                           0x75, 0x3D, 0x41, 0xF0, 0x33, 0x59, 0x10, 0xAD, 0x3A, 0x97, 0x71, 0x04, 0xF1, 0xAA, 0xF6, 0xC3,
                           0x74, 0x27, 0x16, 0xA9, 0x75, 0x5D, 0x11, 0xB8, 0xEE, 0xD6, 0x90, 0x47, 0x7F, 0x44, 0x5C, 0x5D,
                           0x27, 0x20, 0x8B, 0x2E, 0x28, 0x43, 0x30, 0xFA, 0x3D, 0x30, 0x14, 0x23, 0xFA, 0x7F, 0x2D, 0x08,
                           0x6E, 0x0A, 0xD0, 0xB8, 0x92, 0xB9, 0xDB, 0x54, 0x4E, 0x45, 0x6D, 0x3F, 0x0D, 0xAB, 0x85, 0xD9,
                           0x53, 0xC1, 0x2D, 0x34, 0x0A, 0xA8, 0x73, 0xED, 0xA7, 0x27, 0xC8, 0xA6, 0x49, 0xDB, 0x7F, 0xA6,
                           0x37, 0x40, 0xE2, 0x5E, 0x9A, 0xF1, 0x53, 0x3B, 0x30, 0x7E, 0x61, 0x32, 0x99, 0x93, 0x11, 0x0E,
                           0x95, 0x19, 0x4E, 0x03, 0x93, 0x99, 0xC3, 0x82, 0x4D, 0x24, 0xC5, 0x1F, 0x22, 0xB2, 0x6B, 0xDE,
                           0x10, 0x24, 0xCD, 0x39, 0x59, 0x58, 0xA2, 0xDF, 0xEB, 0x48, 0x16, 0xA6, 0xE8, 0xAD, 0xED, 0xB5,
                           0x0B, 0x1F, 0x6B, 0x56, 0xD0, 0xB3, 0x06, 0x0F, 0xF0, 0xF1, 0xC4, 0xCB, 0x0D, 0x0E, 0x00, 0x1D,
                           0xD5, 0x9D, 0x73, 0xBE, 0x12};

int read_file(const char *file_path, char **file_contents, size_t *file_size) {
    FILE* fh = NULL;
    size_t fs = 0;

    if(file_path == NULL) {
        printf("read_file: Error. Missing file path.\r\n" );
        return EXIT_FAILURE;
    }

    //Open input file
    fh = fopen(file_path, "rb");

    //Failed to open input file?
    if (fh == NULL)
    {
        //User message
        printf("read_file: Error. Cannot open %s!\r\n", file_path);
        //Report an error
        return EXIT_FAILURE;
    }

    //Retrieve the length of the file
    fseek(fh, 0, SEEK_END);
    fs = ftell(fh);
    fseek(fh, 0, SEEK_SET);

    *file_contents = (char*)malloc(fs);

    if (*file_contents == NULL)
    {
        //User message
        printf("read_file: Error. Failed to allocate memory for the input file!\r\n");

        //Clean-up side effects
        fclose(fh);

        //Report an error
        return EXIT_FAILURE;
    }

    //Read the contents of the file
    fread(*file_contents, fs, 1, fh);

    // Copy the file size to the input parameter
    *file_size = fs;

    //Close input file
    fclose(fh);

    return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
    error_t error;
    uint8_t digest[64];
    uint8_t signature[512];
    size_t signatureLength;
    uint8_t randSeed[32];
    size_t randSeedSize;
    RsaPublicKey publicKey;
    RsaPrivateKey privateKey;

    #if USE_OPENSSL_KEYS
    char_t *private_key_raw;
    size_t private_key_raw_size;
    char_t *public_key_raw;
    size_t public_key_raw_size;
    #endif

    error = NO_ERROR;

    // Initialize RSA public and private keys memory
    rsaInitPublicKey(&publicKey);
    rsaInitPrivateKey(&privateKey);

    // start of exception handling block
    do
    {
        #if USE_CYCLONE_KEYS
        printf("Initializing CSPRNG...\n");
        // Generatea CSPRNG Seed (32 bytes)
        // https://man7.org/linux/man-pages/man2/getrandom.2.html
        // getrandom() was introduced in version 3.17 of the Linux kernel.
        randSeedSize = getrandom(randSeed, 32, GRND_RANDOM);
        if (randSeedSize != 32)
        {
            // Debug message
            printf("Error. CSPRNG Seed failed (%d)\r\n", error);
            break;
        }
        // Initialize PRNG Algo
        error = yarrowInit(&yarrowContext);
        if (error)
        {
            printf("Error. CSPRNG initialization failed (%d)\r\n", error);
            break;
        }

        // Seed PRNG
        error = yarrowSeed(&yarrowContext, randSeed, randSeedSize);
        if (error)
        {
            printf("Error. Failed to seed CSPRNG (%d)\r\n", error);
            break;
        }
        printf("Done.\n");

        // Create a key-pair RSA 2048
        // e = 65537, using a frequently used public exponent value
        printf("Generating RSA 2048 key pair...\n");
        error = rsaGenerateKeyPair(YARROW_PRNG_ALGO, &yarrowContext, 2048, 65537, &privateKey, &publicKey);
        if (error)
        {
            printf("Failed to generate key pair.\r\n");
            break;
        }
        printf("Done.\n");
        #endif
        #if USE_OPENSSL_KEYS

        error = read_file("../my_rsa_key.pem",&private_key_raw, &private_key_raw_size);
        if(error)
        {
            printf("Failed to import private key.\n");
            break;
        }

        error = read_file("../my_rsa_public_key.pem",&public_key_raw,&public_key_raw_size);
        if(error)
        {
            printf("Failed to import public key.\n");
            break;
        }

        error = pemImportRsaPrivateKey(private_key_raw,private_key_raw_size,&privateKey);
        if(error)
        {
            printf("Failed to load private key.\n");
            break;
        }

        error = pemImportRsaPublicKey(public_key_raw,public_key_raw_size,&publicKey);
        if(error)
        {
            printf("Failed to load public key.\n");
            break;
        }

        #endif
        printf("Computing SHA256 digest of the messsage...\n");

        // Digest the message to  be signed
        error = sha256Compute(message, sizeof(message), digest);
        if (error)
        {
            printf("Failed to compute Hash.\r\n");
            break;
        }
        printf("Done.\n");

        // Sign the message digest using the previously generated private key
        // RSA PKCS #1 v1.5 signature generation
        printf("Signing the message using RSA 2048 PK...\n");
        error = rsassaPkcs1v15Sign(&privateKey, SHA256_HASH_ALGO,
                                   digest, signature, &signatureLength);

        if (error)
        {
            printf("Could not sign the message.\n");
            break;
        }
        printf("Done.\n");

        // Verify the message
        // RSA PKCS #1 v1.5 signature verification
        printf("Verifying the signature...\n");
        error = rsassaPkcs1v15Verify(&publicKey, SHA256_HASH_ALGO,
                                     digest, signature, 256);

        if (error)
        {
            printf("Could not verify the message.\n");
            break;
        }
        printf("Done.\n");

        printf("RSA 2048 Signature Generation/Verification Complete.\n");

        // end of exception handling block
    } while (0);

    // Release previously allocated resources
    rsaFreePublicKey(&publicKey);
    rsaFreePrivateKey(&privateKey);

    return NO_ERROR;
}
