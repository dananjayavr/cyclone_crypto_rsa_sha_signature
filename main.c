#include <stdio.h>
#include "core/crypto.h"

int main(int argc, char* argv[]) {
	printf("Hello, World!\n");

    // Create a key-pair RSA 2048 (for the moment, use OpenSSL)

    // Sign the image file (i.e. image.bin) using the previously generated private key

    // Verify the image file
    // TRUE if verified, FALSE if not.
	return 0;
}
