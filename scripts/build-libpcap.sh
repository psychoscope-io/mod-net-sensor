#!/usr/bin/env bash
# Compila um libpcap minimo e ESTATICO para o release do sensor.
#
#   scripts/build-libpcap.sh <prefixo>
#   LIBPCAP_LIBDIR=<prefixo>/lib cargo build --release --locked
#
# Por que: a biblioteca de execucao muda de nome conforme a distribuicao (libpcap.so.0.8 no Debian e
# no Ubuntu, libpcap.so.1 no Fedora), e um binario ligado dinamicamente so roda onde o nome bate.
# Ligado estaticamente, o sensor roda em qualquer uma sem instalar libpcap.
#
# So o necessario para capturar no Linux: sem dbus, rdma, bluetooth, usb, netmap nem libnl (estes
# puxariam dezenas de bibliotecas dinamicas). Precisa de curl, tar, make, gcc, flex e bison.
# LIBPCAP_TARBALL aponta para um tarball ja baixado (o SHA256 e conferido do mesmo jeito).
set -euo pipefail

VERSION=1.10.7
# SHA256 do libpcap-$VERSION.tar.gz, fixado na primeira obtencao (o tcpdump.org nao publica a soma):
# ao subir a versao, baixe, confira a assinatura .sig e atualize os dois valores.
SHA256=0b394ac90dbc0a9838ff97468e05c9c9a3e873dec2514cd58db65d859d296e31

if [ "$#" -ne 1 ]; then
  echo "uso: $0 <prefixo>" >&2
  exit 2
fi
PREFIX="$(mkdir -p "$1" && cd "$1" && pwd)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

TARBALL="${LIBPCAP_TARBALL:-}"
if [ -z "$TARBALL" ]; then
  TARBALL="$WORK/libpcap-$VERSION.tar.gz"
  curl -fsSL --retry 3 -o "$TARBALL" "https://www.tcpdump.org/release/libpcap-$VERSION.tar.gz"
fi

echo "$SHA256  $TARBALL" | sha256sum -c - >&2 || {
  echo "SHA256 do libpcap-$VERSION.tar.gz nao confere" >&2
  exit 1
}

tar -C "$WORK" -xzf "$TARBALL"
cd "$WORK/libpcap-$VERSION"
./configure --prefix="$PREFIX" --disable-shared \
  --disable-dbus --disable-rdma --disable-bluetooth --disable-usb --disable-netmap \
  --without-libnl >&2
make -j"$(nproc)" >&2
make install >&2

# Sem .so ao lado do .a o linker escolhe a versao estatica.
rm -f "$PREFIX"/lib/libpcap.so*
echo "libpcap $VERSION estatico em $PREFIX/lib" >&2
