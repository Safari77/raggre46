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

