#!/bin/sh

# known feature: uses raggre found from path

if [ ! -f test4.txt ]; then
  echo test4.txt missing
  exit 1
fi
_TMP4=$(mktemp tmp4.XXXXXX) || exit 1
raggre -4 test4.txt > ${_TMP4}
cmp test4-ok.txt ${_TMP4} && rm -f ${_TMP4}

if [ ! -f test4invalid.txt ]; then
  echo test4invalid.txt missing
  exit 1
fi
_TMP4=$(mktemp tmp4.XXXXXX) || exit 1
raggre -4 --ignore-invalid test4invalid.txt > ${_TMP4}
cmp test4invalid-ok.txt ${_TMP4} && rm -f ${_TMP4}

if [ ! -f test4-0000.txt ]; then
  echo test4-0000.txt missing
  exit 1
fi
_TMP4=$(mktemp tmp4.XXXXXX) || exit 1
raggre -4 test4-0000.txt > ${_TMP4}
cmp test4-0000-ok.txt ${_TMP4} && rm -f ${_TMP4}

if [ ! -f test6.txt ]; then
  echo test6.txt missing
  exit 1
fi
_TMP6=$(mktemp tmp6.XXXXXX) || exit 1
raggre -6 test6.txt > ${_TMP6}
cmp test6-ok.txt ${_TMP6} && rm -f ${_TMP6}

if [ ! -f test6invalid.txt ]; then
  echo test6invalid.txt missing
  exit 1
fi
_TMP6=$(mktemp tmp6.XXXXXX) || exit 1
raggre -6 --ignore-invalid test6invalid.txt > ${_TMP6}
cmp test6invalid-ok.txt ${_TMP6} && rm -f ${_TMP6}

if [ ! -f test6-0.txt ]; then
  echo test6-0.txt missing
  exit 1
fi
_TMP6=$(mktemp tmp6.XXXXXX) || exit 1
raggre -6 test6-0.txt > ${_TMP6}
cmp test6-0-ok.txt ${_TMP6} && rm -f ${_TMP6}

for ipv6test in "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" "::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe" "ffff:ffff::fff-ffff:ffff:ffff:ffff:ffff:f:ffff:ffff"  "2010:3939:dead::beef-2939:0:0:42::69"; do
  echo "${ipv6test}" | raggre -6 --input-range|raggre -6 --output-range|grep -qx "${ipv6test}" || ( echo ipv6 input-range/output-range fail for \""${ipv6test}"\" ; exit 1 )
done

for ipv4test in "0.0.0.0-255.255.255.255" "0.0.0.1-255.255.255.254" "29.4.5.66-191.253.44.19"; do
  echo "${ipv4test}" | raggre -4 --input-range|raggre -4 --output-range|grep -qx "${ipv4test}" || ( echo ipv4 input-range/output-range fail for \""${ipv4test}"\" ; exit 1 )
done

