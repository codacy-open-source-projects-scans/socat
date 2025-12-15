#! /usr/bin/env bash
# Source: socks5connect-echo.sh

# Copyright Gerhard Rieger and contributors (see file CHANGES)
# Published under the GNU General Public License V.2, see file COPYING

# Performs primitive simulation of a socks5 server with echo function via stdio.
# Accepts and answers SOCKS5 CONNECT request with user+password authentication to
# 8.8.8.8:80, however is does not connect there but just echoes data.
# It is required for test.sh
# For TCP, use this script as:
# socat TCP-L:1080,reuseaddr EXEC:"socks5connect-auth.sh"

#set -vx

if [ "$SOCAT" ]; then
    :
elif type socat >/dev/null 2>&1; then
    SOCAT=socat
else
    SOCAT=./socat
fi

case `uname` in
HP-UX|OSF1)
    CAT="$SOCAT -u STDIN STDOUT"
    ;;
*)
    CAT=cat
    ;;
esac

A="7f000001"
P="0050"

# Read and parse SOCKS5 greeting
read _ v b c1 c2 _ <<<"$($SOCAT -u -,readbytes=4 - |od -t x1)"
#echo "$v $b $c" >&2
if [ "$v" != 05 ]; then echo "$0: Packet1: expected version x05, got \"$v\"" >&2; exit 1; fi
if [ "$b" != 02 ]; then echo "$0: Packet1: expected 02 auth methods, got \"$b\"" >&2; exit 1; fi
if [ "$c1" != 00 ]; then echo "$0: Packet1: expected auth method 00, got \"$c1\"" >&2; exit 1; fi
if [ "$c2" != 02 ]; then echo "$0: Packet1: expected auth method 02, got \"$c2\"" >&2; exit 1; fi
# Send answer
echo -en "\x05\x02"

# Read and parse SOCKS5 user-pass auth
read _ v u0 u1 u2 u3 u4 u5 u6 p0 p1 p2 p3 p4 p5 p6 _ <<<"$($SOCAT -u -,readbytes=15 - |od -t x1)"
#echo "$v $u0 $u1 $u2 $u3 $u4 $u5 $u6 $p0 $p1 $p2 $p3 $p4 $p5 $p6" >&2

u="$u1$u2$u3$u4$u5$u6"
p="$p1$p2$p3$p4$p5$p6"
if [ "$u" != "6e6f626f6479" -o "$p" != "733363723374" ]; then
    echo "$0: Packet2: expected auth \"nobody:s3cr3t\", received \"$u:$p\"" >&2
    echo -en "\x01\xff"
    exit 1
fi
echo -en "\x01\x00"

# Read and parse SOCKS5 connect request
read _ v b c d a1 a2 a3 a4 p1 p2 _ <<<"$($SOCAT -u -,readbytes=10 - |od -t x1)"
#echo "$v $b $c $d $a1 $a2 $a3 $a4 $p1 $p2" >&2
a="$a1$a2$a3$a4"
p="$p1$p2"
if [ "$v" != 05 ];   then echo "$0: Packet3: expected version x05, got \"$v\"" >&2; exit 1; fi
if [ "$b" != 01 ] && [ "$b" != 02 ];   then echo "$0: Packet3: expected connect request 01 or bind request 02, got \"$b\"" >&2; exit 1; fi
if [ "$c" != 00 ];   then echo "$0: Packet3: expected reserved 00, got \"$c\"" >&2; exit 1; fi
if [ "$d" != 01 ];   then echo "$0: Packet3: expected address type 01, got \"$d\"" >&2; exit 1; fi
if [ "$a" != "$A" ]; then echo "$0: Packet3: expected address $A, got \"$a\"" >&2; exit 1; fi
if [ "$p" != "$P" ]; then echo "$0: Packet3: expected port $P, got \"$p\"" >&2; exit 1; fi
if [ "$z" != "" ];   then echo "$0: Packet3: trailing data \"$z\"" >&2; exit 1; fi
# Send answer
echo -en "\x05\x00\x00\x01\x10\x00\x1f\x64\x1f\x64"

# Bind/listen/passive mode
if [ "$b" == 02 ]; then
    sleep 1 	# pretend to be waiting for connection
    echo -en "\x05\x00\x00\x01\x10\xff\x1f\x64\x23\x28"
fi

# perform echo function
exec $CAT
