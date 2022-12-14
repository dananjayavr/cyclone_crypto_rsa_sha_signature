### Prerequisites

 - CMake (project built/tested using CMake 3.23.3)
 - Linux distro (project built/tested on Ubuntu 20.04 LTS on Windows Subsystem for Linux (WSL2))


### Project architecture

 - main.c : main entrypoint
 - check_probable_prime.c : reference implmentation, please see the note below
 - lib/common : common files for CycloneCRYPTO (Open)
 - lib/core : core files for CycloneCRYPTO (Open)
 - lib/cyclone_crypto : complete source code for CycloneCRYPTO (Open)
 - lib/crypto_config.h : used to enable/disable different CRYPTO modules
 - lib/os_port_config.h : contains information about the target platform


### Build 

 - create a 'build' directory at the project root.
 - From within 'build' directory, execute the following commands:
   - cmake ..
   - cmake --build .
- ./rsa_sha_demo will run the demo.


### Using OpenSSL certificates 

 - Activate with the macro definition USE_OPENSSL_KEYS 1 (and USE_CYCLONE_KEYS 0)
 - Generate keypair at the root folder (the program assumes execution from ./build folder)
  - Private key : openssl genrsa -out my_rsa_key.pem 2048
  - Public Key : openssl rsa -in my_rsa_key.pem -outform PEM -pubout -out my_rsa_public.key
 - Build the demo using the steps in the previous step.

  
### Note: 

#### About check_probable_prime.c
  The file check_probable_prime.c is an example imlpementation of checkProbablePrime(), based on some mbedTLS routines (under Apache 2.0 permissive license). This is not a part of CycloneCRYPTO.

  CycloneCRYPTO is mainly oriented towards smaller footprint embedded targets. On such devices the computing cost for calculating a RSA keypair with a software implementation is quite large (~2 minutes). The funciton checkProbablePrime() is provided as a placeholder, so code running on embedded targets (SAMExx, Renesas RA6, etc.) can use hardware acceleration usually provided by MCU vendors.

  However, this is not a big issue for a project running on a x86 based target (ex.Intel).

#### About lib/ folder

  This folder contains all the files/folders available for CycloneCRYPTO suite. Naturally, not all files/folders are used for this demo.
  lib/CMakeLists.txt contains a list of dependencies for the current project.

#### Using OpenSSL

  CycloneCRYPTO is able to import keypairs generated by OpenSSL as long as they conform to the following criteria: 
    - keys are in PEM format
    - No passphrases are used to protect the keys

