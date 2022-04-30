# CBMCrypt

CBMCrypt turns your Commodore 8 bit computer (VIC20, C64, Plus/4, C16, C128) into a crypto machine which uses the 
modern ChaCha20 algorithm for en-/decryption.

# Building CBMCrypt

CBMCrypt was developed using the ACME macro assembler and a makefile is provided which allows to build all variants
of CBMCrypt. Use the following commands when calling `make`:

| Target platform | command |
|-----------------|---------|
| c64 | `make` | 
| VIC20 (At least 8k additional RAM required) | `make VIC20=1`| 
| Plus/4 and C16 | `make PLUS4=1`|
| C128 | `make C128=1` |

The build process results in a disk image called `cbmcrypt.d64` which can be run in emulators or copied on a real
floppy. A shell script `make_all.sh` that runs under Linux is also provided. This script builds all variants in one
go. 

In order to use CBMCrypt one also needs so called key sheets. These can be generated using the keysheet generator,
which is also provided as a Go program and can be found in the `keygen` subfolder. Use `go build` in order to build
it.

Remark for Mac users: The makefile can also be used under macOS. Please use `make MAC=1 ...` and adapt the values of
the variables `ACME`, `C1541` and `WORKDIR` accordingly to reflect the situation on your machine. 
 
# Using CBMCrypt

## Commands
CBMCrypt utilizes a user interface that is inspired by a command line interface. You have to type a command then
you are queried for additional parameters and after that the command is executed. The following commands are
understood by CBMCrypt:

| Command | What is does |
|-|-|
|`x`| Exits CBMCrypt |
|`h`| Print all known commands |
|`clr`| Clears the screen |
|`dir`| Prints a directory listing of the selected floppy drive (8 is the default)|
|`enc`| Encrypts the current contents of the message buffer and stores the ciphertext on floppy. This command only works after the `ini` comand was called successfully |
|`dec`| Decrypts a file read from the floppy and stores the plaintext in the message buffer. This command only works after the `ini` comand was called successfully. The message buffer has to be empty when attempting a decryption |
|`dev`| Can be used to select the device number (8-11) of the floppy drive to use for IO |
|`ste`| Prints the current state of CBMCrypt. In detail is prints the floppy device number and if CBMCrypt has been properly initialized through the `ini` command. If this is the case the key ID of the key used during initialization is also printed |
|`ini`| This command has to be used to initialize the ChaCha20 cipher. The value of the key, its key ID a nonce prefix and a check value have to be entered. As its name implies the check value can used to verify that the key value, key ID and nonce perfix have been entered correctly|
|`edt`| This command allows to enter plaintext which is appended to current contents of the message buffer. Enter an empty line in order to leave this command. The maximum message length is currently set to 768 characters |
|`lst`| Lists the current contents of the message buffer|
|`new`| Clears and empties the message buffer|
|`inf`| Prints information about an enrypted file on floppy disk |
|`vic` (Only on C128)| Switches `edt` and `lst` to 40 column mode|
|`vdc` (Only on C128)| Switches `edt` and `lst` to 80 column mode|

## Some background

ChaCha20 is a cipher that makes use of a so called "number only used once" or nonce for short. 

# Generating key sheets

# Some thoughts


