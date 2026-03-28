#!/bin/bash

# known feature: uses raggre found from path

_FAIL_COUNT=0
_TEST_COUNT=0
cd . || exit 1
_TMPDIR=$(mktemp -d tmp.raggre-test.XXXXXX) || exit 1

cleanup() {
  rm -rf "${_TMPDIR}"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $1"
  (( _FAIL_COUNT++ ))
}

run() {
  (( _TEST_COUNT++ ))
}

if [ ! -f test4.txt ]; then
  echo test4.txt missing
  exit 1
fi
run
_TMP4="${_TMPDIR}/test4.out"
raggre -4 test4.txt > "${_TMP4}"
cmp test4-ok.txt "${_TMP4}" || fail "test4.txt aggregation differs from test4-ok.txt"

if [ ! -f test4invalid.txt ]; then
  echo test4invalid.txt missing
  exit 1
fi
run
_TMP4="${_TMPDIR}/test4invalid.out"
raggre -4 --ignore-invalid test4invalid.txt > "${_TMP4}"
cmp test4invalid-ok.txt "${_TMP4}" || fail "test4invalid.txt --ignore-invalid differs from test4invalid-ok.txt"

if [ ! -f test4-0000.txt ]; then
  echo test4-0000.txt missing
  exit 1
fi
run
_TMP4="${_TMPDIR}/test4-0000.out"
raggre -4 test4-0000.txt > "${_TMP4}"
cmp test4-0000-ok.txt "${_TMP4}" || fail "test4-0000.txt aggregation differs from test4-0000-ok.txt"

if [ ! -f test6.txt ]; then
  echo test6.txt missing
  exit 1
fi
run
_TMP6="${_TMPDIR}/test6.out"
raggre -6 test6.txt > "${_TMP6}"
cmp test6-ok.txt "${_TMP6}" || fail "test6.txt aggregation differs from test6-ok.txt"

if [ ! -f test6invalid.txt ]; then
  echo test6invalid.txt missing
  exit 1
fi
run
_TMP6="${_TMPDIR}/test6invalid.out"
raggre -6 --ignore-invalid test6invalid.txt > "${_TMP6}"
cmp test6invalid-ok.txt "${_TMP6}" || fail "test6invalid.txt --ignore-invalid differs from test6invalid-ok.txt"

if [ ! -f test6-0.txt ]; then
  echo test6-0.txt missing
  exit 1
fi
run
_TMP6="${_TMPDIR}/test6-0.out"
raggre -6 test6-0.txt > "${_TMP6}"
cmp test6-0-ok.txt "${_TMP6}" || fail "test6-0.txt aggregation differs from test6-0-ok.txt"

for ipv6test in "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" "::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe" "ffff:ffff::fff-ffff:ffff:ffff:ffff:ffff:f:ffff:ffff"  "2010:3939:dead::beef-2939:0:0:42::69"; do
  run
  echo "${ipv6test}" | raggre -6 --input-range|raggre -6 --output-range|grep -qx "${ipv6test}" || fail "ipv6 input-range/output-range roundtrip for \"${ipv6test}\""
done

for ipv4test in "0.0.0.0-255.255.255.255" "0.0.0.1-255.255.255.254" "29.4.5.66-191.253.44.19"; do
  run
  echo "${ipv4test}" | raggre -4 --input-range|raggre -4 --output-range|grep -qx "${ipv4test}" || fail "ipv4 input-range/output-range roundtrip for \"${ipv4test}\""
done

# ---------------------------------------------------------------------------
# stdin input (no file argument)
# ---------------------------------------------------------------------------

run
_RESULT=$(printf '10.0.0.0/24\n10.0.1.0/24\n' | raggre -4)
[ "${_RESULT}" = "10.0.0.0/23" ] || fail "stdin input: got '${_RESULT}', expected '10.0.0.0/23'"

# ---------------------------------------------------------------------------
# mixed v4+v6 (no -4 or -6 flag)
# ---------------------------------------------------------------------------

run
_RESULT=$(printf '10.0.0.0/24\n2001:db8::/32\n' | raggre | wc -l | tr -d ' ')
[ "${_RESULT}" = "2" ] || fail "mixed v4+v6: expected 2 lines, got ${_RESULT}"

# ---------------------------------------------------------------------------
# --max-length
# ---------------------------------------------------------------------------

# /32 hosts should be clamped to /24
run
_RESULT=$(printf '10.1.2.3\n10.1.2.4\n' | raggre -4 -m 24)
[ "${_RESULT}" = "10.1.2.0/24" ] || fail "--max-length /24: got '${_RESULT}'"

# /128 hosts clamped to /48
run
_RESULT=$(printf '2001:db8:1::1\n2001:db8:1::ffff\n' | raggre -6 -m 48)
[ "${_RESULT}" = "2001:db8:1::/48" ] || fail "--max-length v6 /48: got '${_RESULT}'"

# two /32s in same /31 should aggregate after clamping to /31
run
_RESULT=$(printf '10.0.0.0/32\n10.0.0.1/32\n' | raggre -4 -m 31)
[ "${_RESULT}" = "10.0.0.0/31" ] || fail "--max-length /31 aggregate: got '${_RESULT}'"

# ---------------------------------------------------------------------------
# --exclude
# ---------------------------------------------------------------------------

run
_TMPA="${_TMPDIR}/excl_a.txt"
_TMPB="${_TMPDIR}/excl_b.txt"
echo "10.0.0.0/8" > "${_TMPA}"
echo "10.1.0.0/16" > "${_TMPB}"
_RESULT=$(raggre -4 --exclude "${_TMPB}" "${_TMPA}" | wc -l | tr -d ' ')
# /8 minus /16 should produce multiple prefixes
[ "${_RESULT}" -gt 1 ] || fail "--exclude should split /8 into multiple prefixes, got ${_RESULT} lines"

run
# the excluded /16 must not appear in the result
raggre -4 --exclude "${_TMPB}" "${_TMPA}" | grep -q "10.1.0.0/16" && fail "--exclude did not remove 10.1.0.0/16"

# ---------------------------------------------------------------------------
# --intersect
# ---------------------------------------------------------------------------

run
_TMPA="${_TMPDIR}/isect_a.txt"
_TMPB="${_TMPDIR}/isect_b.txt"
echo "10.0.0.0/8" > "${_TMPA}"
echo "10.1.0.0/16" > "${_TMPB}"
_RESULT=$(raggre -4 --intersect "${_TMPB}" "${_TMPA}")
[ "${_RESULT}" = "10.1.0.0/16" ] || fail "--intersect: got '${_RESULT}', expected '10.1.0.0/16'"

# intersect with no overlap should produce empty output
run
_TMPA="${_TMPDIR}/isect_noa.txt"
_TMPB="${_TMPDIR}/isect_nob.txt"
echo "10.0.0.0/8" > "${_TMPA}"
echo "172.16.0.0/12" > "${_TMPB}"
_RESULT=$(raggre -4 --intersect "${_TMPB}" "${_TMPA}")
[ -z "${_RESULT}" ] || fail "--intersect no overlap should be empty, got '${_RESULT}'"

# ---------------------------------------------------------------------------
# --diff
# ---------------------------------------------------------------------------

# basic diff: common prefix should not appear, unique ones should
run
_TMPA="${_TMPDIR}/diff_a.txt"
_TMPB="${_TMPDIR}/diff_b.txt"
printf '10.0.0.0/24\n10.0.1.0/24\n' > "${_TMPA}"
printf '10.0.0.0/24\n10.0.2.0/24\n' > "${_TMPB}"
_RESULT=$(raggre -4 --diff "${_TMPA}" "${_TMPB}")
echo "${_RESULT}" | grep -q '^- 10.0.1.0/24' || fail "--diff missing '- 10.0.1.0/24', got: ${_RESULT}"

run
echo "${_RESULT}" | grep -q '^+ 10.0.2.0/24' || fail "--diff missing '+ 10.0.2.0/24', got: ${_RESULT}"

run
# 10.0.0.0/24 is in both, should NOT appear in diff output at all
echo "${_RESULT}" | grep -q '10.0.0.0/24' && fail "--diff should not list common prefix 10.0.0.0/24, got: ${_RESULT}"

# diff must NOT aggregate siblings — the two /24s should stay separate, not merge into /23
run
echo "${_RESULT}" | grep -q '/23' && fail "--diff should not aggregate siblings into /23, got: ${_RESULT}"

# diff with identical files should produce no output
run
_TMPA="${_TMPDIR}/diff_same_a.txt"
_TMPB="${_TMPDIR}/diff_same_b.txt"
printf '10.0.0.0/24\n10.0.1.0/24\n' > "${_TMPA}"
printf '10.0.0.0/24\n10.0.1.0/24\n' > "${_TMPB}"
_RESULT=$(raggre -4 --diff "${_TMPA}" "${_TMPB}")
[ -z "${_RESULT}" ] || fail "--diff identical files should produce empty output, got: ${_RESULT}"

# diff with completely disjoint files
run
_TMPA="${_TMPDIR}/diff_dis_a.txt"
_TMPB="${_TMPDIR}/diff_dis_b.txt"
printf '10.0.0.0/24\n' > "${_TMPA}"
printf '192.168.0.0/24\n' > "${_TMPB}"
_RESULT=$(raggre -4 --diff "${_TMPA}" "${_TMPB}")
echo "${_RESULT}" | grep -q '^- 10.0.0.0/24' || fail "--diff disjoint: missing '- 10.0.0.0/24'"

run
echo "${_RESULT}" | grep -q '^+ 192.168.0.0/24' || fail "--diff disjoint: missing '+ 192.168.0.0/24'"

# diff should still deduplicate (remove contained prefixes)
run
_TMPA="${_TMPDIR}/diff_dedup_a.txt"
_TMPB="${_TMPDIR}/diff_dedup_b.txt"
printf '10.0.0.0/8\n10.0.1.0/24\n' > "${_TMPA}"
printf '10.0.0.0/8\n' > "${_TMPB}"
_RESULT=$(raggre -4 --diff "${_TMPA}" "${_TMPB}")
# /24 is contained within /8, so after dedup both sides have just /8 — diff should be empty
[ -z "${_RESULT}" ] || fail "--diff should dedup contained prefixes, got: ${_RESULT}"

# diff with IPv6
run
_TMPA="${_TMPDIR}/diff_v6_a.txt"
_TMPB="${_TMPDIR}/diff_v6_b.txt"
printf '2001:db8::/32\n' > "${_TMPA}"
printf '2001:db8:1::/48\n' > "${_TMPB}"
_RESULT=$(raggre -6 --diff "${_TMPA}" "${_TMPB}")
echo "${_RESULT}" | grep -q '^- 2001:db8::/32' || fail "--diff v6: missing '- 2001:db8::/32'"

run
echo "${_RESULT}" | grep -q '^+ 2001:db8:1::/48' || fail "--diff v6: missing '+ 2001:db8:1::/48'"

# ---------------------------------------------------------------------------
# --stats
# ---------------------------------------------------------------------------

run
_RESULT=$(printf '10.0.0.0/24\n10.0.1.0/24\njunk\n' | raggre -4 --stats 2>&1 >/dev/null)
echo "${_RESULT}" | grep -q 'Lines: 3' || fail "--stats line count: ${_RESULT}"

run
echo "${_RESULT}" | grep -q 'Invalid: 1' || fail "--stats invalid count: ${_RESULT}"

run
echo "${_RESULT}" | grep -q 'IPv4:.*2 -> 1 aggregated' || fail "--stats aggregation count: ${_RESULT}"

# stats should show 0 addresses without negative zero
run
_RESULT=$(printf '' | raggre -4 --stats 2>&1 >/dev/null)
echo "${_RESULT}" | grep -q '\-0' && fail "--stats shows negative zero: ${_RESULT}"

# ---------------------------------------------------------------------------
# --delimiter and --fields
# ---------------------------------------------------------------------------

# basic cut-like extraction: field 2 from colon-delimited
run
_RESULT=$(printf 'junk:10.0.0.0/24:more\njunk:10.0.1.0/24:more\n' | raggre -4 -d : -f 2)
[ "${_RESULT}" = "10.0.0.0/23" ] || fail "-d : -f 2: got '${_RESULT}', expected '10.0.0.0/23'"

# field 1
run
_RESULT=$(printf '192.168.1.0/24:garbage\n' | raggre -4 -d : -f 1)
[ "${_RESULT}" = "192.168.1.0/24" ] || fail "-d : -f 1: got '${_RESULT}'"

# negative field: -1 = last
run
_RESULT=$(printf 'a:b:10.0.0.0/24\n' | raggre -4 -d : -f=-1)
[ "${_RESULT}" = "10.0.0.0/24" ] || fail "-d : -f -1: got '${_RESULT}'"

# negative field: -2 = second-to-last
run
_RESULT=$(printf 'a:10.0.0.0/24:c\n' | raggre -4 -d : -f=-2)
[ "${_RESULT}" = "10.0.0.0/24" ] || fail "-d : -f=-2: got '${_RESULT}'"

# multiple fields: extract v4 from field 1 and v6 from field 3
run
_RESULT=$(printf '10.0.0.0/24:junk:2001:db8::/32\n' | raggre -d : -f 1,-1)
echo "${_RESULT}" | grep -q '10.0.0.0/24' || fail "multi-field v4 missing: got '${_RESULT}'"

# tab delimiter
run
_RESULT=$(printf '10.0.0.0/24\tgarbage\n10.0.1.0/24\tmore\n' | raggre -4 -d "$(printf '\t')" -f 1)
[ "${_RESULT}" = "10.0.0.0/23" ] || fail "tab delimiter: got '${_RESULT}'"

# U+XXXX delimiter specification (U002C = comma)
run
_RESULT=$(printf '10.0.0.0/24,garbage\n' | raggre -4 -d U002C -f 1)
[ "${_RESULT}" = "10.0.0.0/24" ] || fail "U002C delimiter: got '${_RESULT}'"

# U+XXXX with plus sign
run
_RESULT=$(printf '10.0.0.0/24,junk\n' | raggre -4 -d U+002C -f 1)
[ "${_RESULT}" = "10.0.0.0/24" ] || fail "U+002C delimiter: got '${_RESULT}'"

# invalid UTF-8 lines should be skipped and counted in stats
run
_RESULT=$(printf '10.0.0.0/24\n' | cat - /dev/urandom | head -c 4096 | raggre -4 -d : -f 1 --stats 2>&1 >/dev/null)
echo "${_RESULT}" | grep -q 'UTF-8 errors:' || fail "--stats missing UTF-8 errors count with delimiter mode"

# --delimiter without --fields should fail
run
raggre -4 -d : < /dev/null 2>/dev/null && fail "-d without -f should fail"

# --fields without --delimiter should fail
run
raggre -4 -f 1 < /dev/null 2>/dev/null && fail "-f without -d should fail"

# field 0 should be rejected
run
raggre -4 -d : -f 0 < /dev/null 2>/dev/null && fail "-f 0 should be rejected"

# CESU-8 surrogate delimiter should be rejected (U+D800)
run
raggre -4 -d UD800 -f 1 < /dev/null 2>/dev/null && fail "surrogate U+D800 should be rejected"

# out-of-range field should silently produce no match (not crash)
run
_RESULT=$(printf 'a:b\n' | raggre -4 -d : -f 99)
[ -z "${_RESULT}" ] || fail "out-of-range field should produce empty output, got '${_RESULT}'"

# negative out-of-range field should also work
run
_RESULT=$(printf 'a:b\n' | raggre -4 -d : -f=-99)
[ -z "${_RESULT}" ] || fail "negative out-of-range field should produce empty output, got '${_RESULT}'"

# bare IP addresses (no CIDR) with delimiter
run
_RESULT=$(printf 'host1:10.0.0.1\nhost2:10.0.0.2\n' | raggre -4 -d : -f 2 | wc -l | tr -d ' ')
[ "${_RESULT}" = "2" ] || fail "bare IPs with delimiter: expected 2 lines, got ${_RESULT}"

# delimiter with --input-range
run
_RESULT=$(printf 'name:10.0.0.0-10.0.0.255\n' | raggre -4 -d : -f 2 --input-range)
[ "${_RESULT}" = "10.0.0.0/24" ] || fail "delimiter + --input-range: got '${_RESULT}'"

# ---------------------------------------------------------------------------
# --csv-field-number  (CSV without header)
# ---------------------------------------------------------------------------

# basic: extract column 2 from CSV
run
_RESULT=$(printf 'junk,10.0.0.0/24,more\njunk,10.0.1.0/24,more\n' | raggre -4 --csv-field-number 2)
[ "${_RESULT}" = "10.0.0.0/23" ] || fail "--csv-field-number 2: got '${_RESULT}', expected '10.0.0.0/23'"

# column 1
run
_RESULT=$(printf '192.168.1.0/24,garbage\n' | raggre -4 --csv-field-number 1)
[ "${_RESULT}" = "192.168.1.0/24" ] || fail "--csv-field-number 1: got '${_RESULT}'"

# last column
run
_RESULT=$(printf 'a,b,10.0.0.0/24\n' | raggre -4 --csv-field-number 3)
[ "${_RESULT}" = "10.0.0.0/24" ] || fail "--csv-field-number 3 (last col): got '${_RESULT}'"

# quoted fields containing commas
run
_RESULT=$(printf '"hello, world",10.0.0.0/24\n' | raggre -4 --csv-field-number 2)
[ "${_RESULT}" = "10.0.0.0/24" ] || fail "csv quoted field: got '${_RESULT}'"

# quoted field with the IP itself
run
_RESULT=$(printf '"10.0.0.0/24",junk\n' | raggre -4 --csv-field-number 1)
[ "${_RESULT}" = "10.0.0.0/24" ] || fail "csv quoted IP: got '${_RESULT}'"

# out-of-range column should produce no output (not crash)
run
_RESULT=$(printf 'a,b\n' | raggre -4 --csv-field-number 99)
[ -z "${_RESULT}" ] || fail "csv out-of-range column should produce empty output, got '${_RESULT}'"

# CSV with --input-range
run
_RESULT=$(printf 'name,10.0.0.0-10.0.0.255\n' | raggre -4 --csv-field-number 2 --input-range)
[ "${_RESULT}" = "10.0.0.0/24" ] || fail "csv + --input-range: got '${_RESULT}'"

# CSV with --stats
run
_RESULT=$(printf 'a,10.0.0.0/24\nb,10.0.1.0/24\nc,junk\n' | raggre -4 --csv-field-number 2 --stats 2>&1 >/dev/null)
echo "${_RESULT}" | grep -q 'Lines: 3' || fail "csv --stats line count: ${_RESULT}"

run
echo "${_RESULT}" | grep -q 'Invalid: 1' || fail "csv --stats invalid count: ${_RESULT}"

# ---------------------------------------------------------------------------
# --csv-field-name  (CSV with header)
# ---------------------------------------------------------------------------

# basic: extract by header name
run
_RESULT=$(printf 'name,network,comment\njunk,10.0.0.0/24,more\njunk,10.0.1.0/24,more\n' | raggre -4 --csv-field-name network)
[ "${_RESULT}" = "10.0.0.0/23" ] || fail "--csv-field-name network: got '${_RESULT}', expected '10.0.0.0/23'"

# header name with whitespace
run
_RESULT=$(printf '"IP Address",name\n10.0.0.0/24,foo\n10.0.1.0/24,bar\n' | raggre -4 --csv-field-name "IP Address")
[ "${_RESULT}" = "10.0.0.0/23" ] || fail "--csv-field-name with spaces: got '${_RESULT}'"

# header not found should fail
run
raggre -4 --csv-field-name nonexistent < /dev/null 2>/dev/null
_RC=$?
[ "${_RC}" -ne 0 ] || fail "--csv-field-name nonexistent should fail"

# header row is not counted as a data row (only 1 data line)
run
_RESULT=$(printf 'net\n10.0.0.0/24\n' | raggre -4 --csv-field-name net --stats 2>&1 >/dev/null)
echo "${_RESULT}" | grep -q 'Lines: 1' || fail "csv header should not count as data line: ${_RESULT}"

# ---------------------------------------------------------------------------
# CSV mutual exclusion validation
# ---------------------------------------------------------------------------

# --csv-field-number + --csv-field-name together should fail
run
raggre -4 --csv-field-number 1 --csv-field-name net < /dev/null 2>/dev/null && fail "--csv-field-number + --csv-field-name should fail"

# --csv-field-number + --delimiter should fail
run
raggre -4 --csv-field-number 1 -d : -f 1 < /dev/null 2>/dev/null && fail "--csv-field-number + -d should fail"

# --csv-field-name + --delimiter should fail
run
raggre -4 --csv-field-name net -d : -f 1 < /dev/null 2>/dev/null && fail "--csv-field-name + -d should fail"

# --csv-field-number 0 should be rejected (1-based)
run
raggre -4 --csv-field-number 0 < /dev/null 2>/dev/null && fail "--csv-field-number 0 should be rejected"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
if [ "${_FAIL_COUNT}" -eq 0 ]; then
  echo "All ${_TEST_COUNT} tests passed."
else
  echo "${_FAIL_COUNT} of ${_TEST_COUNT} tests FAILED."
  exit 1
fi
