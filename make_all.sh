make cleanup

make clean
make 
cp cbmcrypt.d64 cbmcrypt_c64.d64

make clean
make VIC20=1
cp cbmcrypt.d64 cbmcrypt_vic20.d64

make clean
make PLUS4=1
cp cbmcrypt.d64 cbmcrypt_plus4.d64

make clean
make C128=1
cp cbmcrypt.d64 cbmcrypt_c128.d64
