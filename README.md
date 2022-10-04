### Requirements

1. create key-pair (private + public, rsa2048)
2. sign 'image.bin' with SHA256 (i.e. 'image_sign.bin), using the private key
   i.e. 'image_sign.bin' now holds the 'image.bin' + signature
3. verify 'image_sign.bin' and return TRUE/FALSE if the 'image.bin' is verify okay.
4. Note that I would like to test it aon ubuntu linux machine, and later compile it on vxWorks workbench
5. The project is based on vxWorks-7 with Intel core.