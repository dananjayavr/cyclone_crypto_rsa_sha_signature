### Prerequisites

 - CMake (project built/tested using CMake 3.23.3)
 - Linux distro (project built/tested on Ubuntu 20.04 LTS on Windows Subsystem for Linux (WSL2))


### Project architecture

 - main.c : main entrypoint
 - check_probable_prime.c : reference implmentation, please see the note below
 - lib/common : common files for CycloneCRYPTO (Open)
 - lib/core : core files for CycloneCRYPTO (Open)
 - lib/cyclone_crypto : complete source code for CycloneCRYPTO (Open)

### Build 

 - create a 'build' directory at the project root.
 - From within 'build' directory, execute the following commands:
   - cmake ..
   - cmake --build .
- ./rsa_sha_demo will run the demo.

### Note: 

The file check_probable_prime.c is an example imlpementation of checkProbablePrime(), based on some mbedTLS routines (under Apache 2.0 permissive license). This is not a part of CycloneCRYPTO.

CycloneCRYPTO is mainly oriented towards smaller footprint embedded targets. On such devices the computing cost for calculating a RSA keypair with a software implementation is quite large (~2 minutes). The funciton checkProbablePrime() is provided as a placeholder, so code running on embedded targets (SAMExx, Renesas RA6, etc.) can use hardware acceleration usually provided by MCU vendors.

Naturally, this is not a big issue for a project running on a x86 based target (ex.Intel).