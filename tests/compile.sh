echo "Cleaning bin folder..."
mkdir -p bin
rm bin/*

echo "Compiling binaries"
mkdir -p sources
cd sources
for i in *.c; do gcc -o ../bin/$i.out $i; done

echo "Done!"