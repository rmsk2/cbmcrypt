# On MacOS use make MAC=1
# On Linux simply use make

all: cbmcrypt cbmcrypt.d64

ifdef MAC
ACME=../acme/acme
C1541=/Applications/vice-gtk3-3.5/bin/c1541
WORKDIR=/Users/martin/data/c64_mandelbrot
else
ACME=acme
C1541=c1541
WORKDIR=.
endif

clean:
	rm cbmcrypt
	rm cbmcrypt.d64
	rm cbmcrypt.txt

cbmcrypt: main.a 
	$(ACME) -l cbmcrypt.txt main.a

cbmcrypt.d64: cbmcrypt
	$(C1541) -format cbmcrypt,cc d64 $(WORKDIR)/cbmcrypt.d64 -write $(WORKDIR)/cbmcrypt
