# On MacOS use make MAC=1
# On Linux simply use make

all: cbmcrypt cbmcrypt.d64

ifdef MAC
ACME=../acme/acme
C1541=/Applications/vice-x86-64-sdl2-3.7.1/bin/c1541
WORKDIR=/Users/martin/data/cbmcrypt
else
ACME=acme
C1541=c1541
WORKDIR=.
endif

PLATFORM = C64

ifdef VIC20
PLATFORM=VIC20
endif	

ifdef PLUS4
PLATFORM=PLUS4
endif	

ifdef C128
PLATFORM=C128
endif	

PLATFORM_FILES = platform.a c64.a vic20.a plus4.a c128.a

cleanup:
	rm cbmcrypt_c64.d64
	rm cbmcrypt_vic20.d64
	rm cbmcrypt_plus4.d64
	rm cbmcrypt_c128.d64

clean:
	rm cbmcrypt
	rm cbmcrypt.d64
	rm cbmcrypt.txt

cbmcrypt: $(PLATFORM_FILES) main.a arith16.a string.a repl.a crypto.a disk_io.a
	$(ACME) -D$(PLATFORM)=1 -l cbmcrypt.txt main.a

cbmcrypt.d64: cbmcrypt
	$(C1541) -format cbmcrypt,cc d64 $(WORKDIR)/cbmcrypt.d64 -write $(WORKDIR)/cbmcrypt
