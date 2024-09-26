## usage
Make directory build
```
mkdir build
cmake -S . -B build
cd build
cmake --build .
```
```
./local_client
```

## Install cmake
```
sudo apt install cmake
```

## Install Libcoap
download libcoap pada https://github.com/obgm/libcoap
```
sudo chmod 777 autogen.sh
./autogen.sh
./configure --disable-documentation --with-openssl
make
sudo make install
```

## Install tshark
Untuk me-record packet masuk packet keluar
```
sudo apt install -y tshark
```