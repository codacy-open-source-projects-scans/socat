#! /usr/bin/env bash
# source: proxyecho.sh
# Copyright Gerhard Rieger and contributors (see file CHANGES)
# Published under the GNU General Public License V.2, see file COPYING

# perform primitive simulation of a proxy server with echo function via stdio.
# accepts and answers correct HTTP CONNECT requests, but then just echoes data.
# it is required for test.sh
# for TCP, use this script as:
# socat TCP-L:8080,reuseaddr,crlf SYSTEM:"proxyecho.sh"

# 20230423  GR Added option -V to require particular HTTP version

if type socat >/dev/null 2>&1; then
    SOCAT=socat
else
    SOCAT=./socat
fi

case `uname` in
HP-UX|OSF1)
    CAT="$SOCAT -u stdin stdout"
    ;;
*)
    CAT=cat
    ;;
esac

SPACES=" " REQVER=1.0
while [ -n "$1" ]; do
    case "$1" in
    -w) n="$2"; while [ "$n" -gt 0 ]; do SPACES="$SPACES "; n=$((n-1)); done
	shift ;;
    -V) shift; REQVER="$1" ;;
    #-s) STAT="$2"; shift ;;
    esac
    shift
done

# read and parse HTTP request
read l
if ! echo "$l" |grep -E '^CONNECT +[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+ +HTTP/[1-3].[0-9]$' >/dev/null
then
    echo "HTTP/1.0${SPACES}500 Bad Request"
    echo
    exit
fi
if ! echo "$l" |grep -E '^CONNECT +[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+ +HTTP/'"$REQVER"'$' >/dev/null
then
    echo "HTTP/1.0${SPACES}426 Upgrade Required"
    echo
    exit
fi

# read more headers until empty line
while [ -n "$l" ]; do
    read l
done

# send status
echo "HTTP/$REQVER${SPACES}200 OK"
# send empty line
echo

# perform echo function
exec $CAT
