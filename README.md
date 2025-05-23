# CBMCrypt

CBMCrypt turns your Commodore 8 bit computer (VIC20, C64, Plus/4, C16, C128) into a crypto machine which uses the 
modern [ChaCha20](https://datatracker.ietf.org/doc/html/rfc8439) algorithm for en-/decryption.

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

## LOADing and RUNning CBMCrypt

Use `LOAD"*",8,1` or `LOAD"CBMCRYPT",8` followed by `RUN` in order to start CBMCrypt. 

## Commands

CBMCrypt utilizes a user interface that is inspired by a command line interface. You have to type a command followed by enter, then
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
|`edt`| This command allows to enter plaintext which is appended to current contents of the message buffer. Enter an empty line in order to return to the command prompt. The maximum message length is currently set to 768 characters |
|`lst`| Lists the current contents of the message buffer|
|`new`| Clears and empties the message buffer|
|`inf`| Prints information about an enrypted file on floppy disk |
|`vic` (Only on C128)| Switches `edt` and `lst` to 40 column mode|
|`vdc` (Only on C128)| Switches `edt` and `lst` to 80 column mode|

## Some cryptographic background

ChaCha20 is a stream cipher that makes use of a so called "number only used once" or nonce for short. When the same key and nonce are used 
for two different messages these messages can simply be XORed together. Doing this the attacker gets the XOR of the two plaintexts, which
in turn can probably be separated through statistical methods. CBMCrypt attempts to prevent this from happening by assigning each party 
a unique nonce prefix in such a way that all nonces generated by two different users will differ at least in this prefix. Additionally 
a so called message number has to be entered when performing an encryption. The message number does not need to be random but it must 
never be repeated for the same key so it is probably the easiest to simply use 1,2,3, .... up to 999. This leaves room for 999 messages 
per user per key, which should be more than enough.

## The file format

The file format used by CBMCrypt is very simple:

```
                   12
        |         Nonce        |
    2           2          10       2       1-768
| KeyID | Nonce-Prefix | Nonce | Length | Ciphertext
```

Two bytes of the key ID are followed by the 12 bytes of the nonce, which in turn consits of the two byte nonce prefix and additional 10
bytes. After that follows a two byte length field which specifies the length of the contained ciphertext. 


# Generating key sheets

Assuming that a group of `n` persons or parties wants to use CBMCrypt, then each of these persons has to be provided with a key sheet
that lists for each key: 

- The key value
- The key ID
- The nonce prefix of the corresponding party for that key
- The check value

As the nonce prefix is different for each party `n` key sheets have to be prepared. The group of people also has to agree for how long 
a specific key has to be used, i.e. they have to agree when to change the key that is to be used when encrypting a new message. In the past
key sheets for cryto machines were typically issued for a month and the key was changed daily. CBMCrypt comes with a key sheet generator
called `keygen` that has a CLI. It can be configured using the following options:

```
Usage of ./keygen:
  -copies uint
    	Number of copies, i.e. number of participants (default 2)
  -key-len uint
    	Number of characters in key (default 16)
  -num-keys uint
    	Number of keys on sheet (default 31)
  -renderer string
    	How to render the key sheet (default "default")
  -title string
    	Title of the key sheet (default "Default")
```

`-copies` has to specify how many parties (and therefore key sheets) have to be prepared. `-key-len` can be used to change the number
of characters in a key. The longer a key the better but longer keys are also more tedious to enter. The maximum number of key characters
is 32 and the minimum is 15. `-num-keys` determines how many key are to be generated. `-title` can be used to name the group of people
the key sheet is intended to be used by. `-renderer` determines how the key sheets are formatted. The following values are allowed:

| Name | Description |
|-|-|
|`default`| Only prints the raw values to `stdout`|
|`txt`| Prints formatted text files to `stdout`|
|`file`| Save the formatted text files in files named `copy_nr_0..n.txt`|

Example for a key sheet generated by `./keygen -copies 2 -renderer txt -title "Test-title" -num-keys 4`:

```
                Test-title

                Copy Nr. 0

-------------------------------------------
|       Key        |  ID  | Nonc | Check  |
-------------------------------------------
| uKFjJ6YGj2831nJ8 | aa27 | 913c | 4aee66 |
| 7TIRAJ3krt+zSsHg | d66d | 83b1 | 98a81e |
| 08S26Pzy3hiZrbka | b8d2 | 2522 | 65e9c6 |
| xARKCumDHIV19He9 | 93d5 | 309a | 82fd61 |
-------------------------------------------
```

# Some thoughts

## Performance

ChaCha20 is a modern cipher and CBMCrypt implements the full version and not some reduced round or dumbed down variant. Nonetheless
a C64 can en-/decrypt data at about 300 Bytes/sec, i.e. the speed by which a C64 could have sent data via a 2400 Baud modem in its day
or roughly half the speed by which it could have written data to a floppy. I find it surprising that a C64 can encrypt data using a modern 
cipher at a speed which even 35 years ago would have been absolutely acceptable.

## Advantages of using historical computers for cryptography

At least the Commodore 8 bit computers provide an execution environment where memory management is absolutely deterministic, i.e. no 
sensitive material is ever swapped to disk or moved to other memory locations. Additionally these machines are trustworthy in that 
sense that it is in principle possible to know what they exactly do at each point in time. In fact they are understandable to 
such a degree that several highly compatible re-implementations (in hard- and software) do exist.

These old machines also have another very desirable property from a security point of view. They can be put in a known good state
by simply switching them off and on again. I.e. even if they are compromised there is no way to persist malware inside these
systems because the operating system is in ROM and there is no other from of non volatile memory of any sort in them.

In modern systems we may find these properties in Smart cards and other dedicated security hardware, but these systems do not provide
any means of interacting with them without attaching them to a "real" computer. These old machines on the other hand integrate a keyboard
and hardware to interface with a display, i.e. a TV or monitor.

Another security relevant property is the fact that these systems are inherently air gapped as they do not contain networking hardware
and especially no radios (WiFi, Bluetooth, GSM, 4G, 5G, ...).

## Are you seriously proposing to use old computers for crypto?

Well, not really. But this project shows that you can implement modern (symmetric) cryptographic algorithms as part of a usable piece
of software on more or less primitive hardware. This is in my opinion relevant for the ongoing discussion about regulating the use
of cryptographic algorithms by the general public. 

If practically secure cryptographic algorithms can be implemented on a class of computer systems that in principle can be and in fact 
have been built by people with the relevant knowledge but very limited resources it becomes obvious that regulating the use of 
cryptography in an absolute sense requires in essence regulating knowledge and general purpose computing. 