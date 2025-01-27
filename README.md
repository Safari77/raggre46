# raggre46

`raggre4`
Aggregate IPv4 network addresses.

`raggre6`
Aggregate IPv6 network addresses.

This is a rust program.  Dependencies: `clap`.  Random IP generators
`ruran4` and `ruran6` require `rand`.

By default IP addresses are accepted if /nn network specified is invalid; for example
1.4.5.6/16 is accepted and processed as 1.4.0.0/16; if you wish to ignore
them, use parameter `--ignore-invalid`, then such addresses are silently
ignored.

This program may or may not be suitable for your use case, feel free to read
the code and make a pull request.  https://github.com/Safari77/raggre46

```
benchmark of this program raggre4
    vs
CIDR network aggregation and filtering - Horms, at verge.net.au, v1.0.2 (C code)
    vs
ISC aggregate 1.6, coded by a committee? (C code)
    vs
aggregate6 1.0.14 by Job Snijders (Python)
```
```
$ wc -l shuf4.txt
200000 shuf4.txt

$ time ./raggre4 < shuf4.txt | sha256sum
af202604d655dd1af52d97c63fe9eddb748775526b9269ec6ebcfc9824f5c49c  -

real    0m0,058s
user    0m0,027s
sys     0m0,065s

$ time verge-aggregate < shuf4.txt | sha256sum
af202604d655dd1af52d97c63fe9eddb748775526b9269ec6ebcfc9824f5c49c  -

real    0m3,956s
user    0m3,935s
sys     0m0,006s

$ time aggregate -m32 < shuf4.txt > out4_isc.txt
aggregate: maximum prefix length permitted will be 32

real    5m53,334s
user    5m52,841s
sys     0m0,028s
$ sha256sum out4_isc.txt
af202604d655dd1af52d97c63fe9eddb748775526b9269ec6ebcfc9824f5c49c  out4_isc.txt

$ time aggregate6 < shuf4.txt | sha256sum
af202604d655dd1af52d97c63fe9eddb748775526b9269ec6ebcfc9824f5c49c  -

real	0m2,519s
user	0m2,442s
sys	0m0,076s

$ calc 352.841/0.027
    ~13068.18518518518518518518518518518518518518518518518519
$
```
