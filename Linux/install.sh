#!/bin/bash

set -u
set -e

mkdir -p downloads

mkdir -p tmp
mkdir -p bin
mkdir -p lib

COMP_DIR=`pwd`
export PATH=$PATH:$COMP_DIR/bin/

echo -e "[+] Compiling MUSL"
# Install MUSL
curl -L -o $COMP_DIR/tmp/musl-$MUSL_VER.tgz https://musl.libc.org/releases/musl-$MUSL_VER.tar.gz
tar -xf $COMP_DIR/tmp/musl-$MUSL_VER.tgz -C $COMP_DIR/tmp/

# MUSL is expecting these to be called something specific
ln -fs /usr/bin/ranlib $COMP_DIR/bin/i386-ranlib
ln -fs /usr/bin/ar $COMP_DIR/bin/i386-ar
pushd $COMP_DIR/tmp/musl-$MUSL_VER > /dev/null

./configure --host=i386 --build=i386 CC="gcc -m32" --prefix=$COMP_DIR/lib/musl --exec-prefix=$COMP_DIR/ --syslibdir=$COMP_DIR/lib/musl/lib --with-malloc=oldmalloc --disable-shared
make -j4
make install

# "Patch" the musl-gcc script and specs file
echo -e '#!/bin/sh\nexec ${REALGCC:-gcc -m32} "$@" -specs "'$COMP_DIR'/lib/musl/lib/musl-gcc.specs"' > $COMP_DIR/bin/musl-gcc
chmod +x $COMP_DIR/bin/musl-gcc
/bin/sh $COMP_DIR/tmp/musl-$MUSL_VER/tools/musl-gcc.specs.sh $COMP_DIR/lib/musl/include/ $COMP_DIR/lib/musl/lib $COMP_DIR/lib/musl/lib/ld-musl-i386.so.1 | sed 's/^-dynamic/-m elf_i386 -dynamic/' > $COMP_DIR/lib/musl/lib/musl-gcc.specs

popd > /dev/null


echo -e "\t[+] Installing UZLib"

# install uzlib

curl -L -o $COMP_DIR/tmp/uzlib-$UZLIB_VER.tgz https://github.com/pfalcon/uzlib/archive/v$UZLIB_VER.tar.gz
tar -xf $COMP_DIR/tmp/uzlib-$UZLIB_VER.tgz -C $COMP_DIR/tmp/

pushd $COMP_DIR/tmp/uzlib-$UZLIB_VER > /dev/null

CC="musl-gcc -static" CFLAGs="-fno-stack-protector -fPIC" make -j4

mkdir -p $COMP_DIR/lib/uzlib/
cp -r $COMP_DIR/tmp/uzlib-$UZLIB_VER/lib $COMP_DIR/lib/uzlib/lib
cp -r $COMP_DIR/tmp/uzlib-$UZLIB_VER/src $COMP_DIR/lib/uzlib/src

popd > /dev/null

# install mbedtls
echo -e "\t[+] installing mbedtls"

curl -L -o $COMP_DIR/tmp/mbedtls-$MBED_VER.tgz https://github.com/ARMmbed/mbedtls/archive/v$MBED_VER.tar.gz
tar -xf $COMP_DIR/tmp/mbedtls-$MBED_VER.tgz -C $COMP_DIR/tmp

pushd $COMP_DIR/tmp/mbedtls-$MBED_VER > /dev/null

mkdir -p $COMP_DIR/lib/mbedtls/

# Patch makefile
COMP_DIR_ESC=$(echo $COMP_DIR | sed 's/\//\\\//g')
sed -i "s/^DESTDIR=\/usr\/local$/DESTDIR=$COMP_DIR_ESC\/lib\/mbedtls/" Makefile

CC="musl-gcc -static" CFLAGS="-fno-stack-protector -fPIC" make -j4 DESTDIR="$COMP_DIR/lib/mbedtls"
make install
 
popd > /dev/null

# install curl
echo -e "\t[+] installing libcurl"

curl  -L -o $COMP_DIR/tmp/libcurl-$LIBCURL_VER.tgz https://curl.haxx.se/download/curl-$LIBCURL_VER.tar.gz
tar -xf $COMP_DIR/tmp/libcurl-$LIBCURL_VER.tgz -C $COMP_DIR/tmp

pushd $COMP_DIR/tmp/curl-$LIBCURL_VER > /dev/null

# Patch to fix https://github.com/curl/curl/issues/2899 
echo '--- mbedtls.c.orig	2020-09-02 16:10:39.698696366 +0100 
+++ mbedtls.c	2020-08-18 11:33:41.409376242 +0100
@@ -814,6 +814,8 @@
   if(ret <= 0) {
     if(ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
       return 0;
+    else if(!ret)
+      return 0;
 
     *curlcode = (ret == MBEDTLS_ERR_SSL_WANT_READ) ?
       CURLE_AGAIN : CURLE_RECV_ERROR;
' > mbedtls.patch

patch -u ./lib/vtls/mbedtls.c -i mbedtls.patch

rm mbedtls.patch

CC="musl-gcc -static" CFLAGS="-fno-stack-protector" ./configure --prefix=$COMP_DIR/lib/curl/ --enable-http --disable-ftp --disable-ldap   --disable-file --disable-ldaps --disable-telnet --disable-rtsp   --disable-dict --disable-tftp --disable-pop3 --disable-imap   --disable-smb --disable-smtp --disable-gopher --without-libssh2   --without-librtmp --disable-versioned-symbols --without-ssl --with-mbedtls=$COMP_DIR/lib/mbedtls --with-ca-bundle=./cacert.pem --enable-static

make -j4
make install

popd > /dev/null

export LIB_DIR=$COMP_DIR/lib/

pushd ./Linux/src/ > /dev/null

export OUTPUT_DIR=$COMP_DIR/linux_implant/

make all
make debug

popd > /dev/null

# tar -czvf $COMP_DIR/artifacts.tgz $COMP_DIR/lib $COMP_DIR/bin
