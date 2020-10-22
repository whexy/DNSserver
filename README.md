# DNS Server

A DNS Server implemented by Python with powerful lib ``dnslib``.

**Not a DNS proxy!**

Typically it's a homework from SUSTech CS305 Computer Networking. Thought it was easy but it turned out that it's far more complicated than any other homework I had in this course.



## Features

- With ``FLAG_TS_ITER`` set to ``True``, NS records can be also parsed into IP address, which is exactly what a real DNS server should do.

- `CNAME` answers are automatically attached with `A` type IP.

![](https://i.loli.net/2020/10/22/fyqXa7VEtPidKuZ.png)

