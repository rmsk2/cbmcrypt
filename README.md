# CBMCrypt

CBMCrypt turns your Commodore 8 bit computer (VIC20, C64, Plus/4, C16, C128) into a crypto machine which uses the 
modern ChaCha20 algorithm for en-/decryption.

# Building CBMCrypt

CBMCrypt was developed using the ACME macro assembler and a makefile is provided which allows to build all variants
of CBMCrypt. Use the following commands when calling `make`:

| Target platform | command |
|-----------------|---------|
| c64 | make | 
| VIC20 (At least 8k additional RAM required) | make VIC20=1| 
| Plus/4 and C16 | make PLUS4=1|
| C128 | make C128=1 |


