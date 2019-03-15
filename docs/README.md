# h2sim - HTTP2 Simple Application Framework
For 3GPP R15 5G SBI HTTP/2 NF Simulator in C using nghttp2.
By Lee Yongjae, Telcoware,Inc., setup74@telcoware.com,
Version: 0.2.1 at 2019-03-13.
See: [https://github.com/setup74/h2simple](https://github.com/setup74/h2simple)


## Introduction

Nghttp2 has as nice and clean event modeled C api,
But the the http client/server code in nghttp2 pacakge
are built on C++/boost, not for clean C users.

So new HTTP2 stack layer for standalone C is built, named http2simple.
And goes with client and server simulator example code.



## Files

h2sim library example application:
- h2cli.c h2svr.c: h2sim app example code for client and server simulator
- NOTE: use -DTLS_MODE=1 option to be built with openssl library

h2sim library files:
- h2.h: the h2sim API defintion
- h2_priv.h: h2sim library private header; NOT FOR APPLICATION
- h2_msg.c, h2_sess.c, h2_io.c: h2sim library implementation

tls utilities:
- genkey_ex.sh: generates eckey.pem, eccert.pem
- genkey_rsa.sh: generates rsakey.pem, rsacert.pem


## Build

need nghttp2 installed:
- env variable NGHTTP2_INCDIR and NGHTTP2_LIBDIR should be set
  if nghttp2 is not installed in /usr/local/

just run make:
- hsim/libh2sim.a, h2svr, h2cli is generated


## Abbrevations

- h2: http2
- nv: name value
- wr: write
- rd: read
- hdr: header
- msg: message
- req: request
- rsp: response
- prm: promise
- strm: stream
- sess: session
- ctx: context


# h2cli and h2svr Run Examples

server with response cases:
```
./h2svr -S http://0.0.0.0:8080 -S https://0.0.0.0:8081 \
  -m POST   -p /user/ -s 200 \
            -x content-type=application/json -t '{ "RESULT" : "SUCCESS" }' \
  -m GET    -p /user/ -s 200 \
            -x content-type=application/json -t '{ "USER_NAME" : "somebody" }' \
  -m DELETE -p /user/ -s 200 \
  -m GET    -p /user2/ -s 404 
```

server with reponse cases and push promise:
```
./h2svr -S http://0.0.0.0:8080 -S https://0.0.0.0:8081 \
  -m POST -p /user1k/ -s 200 -x content-type=application/json -e 1k \
     -o /user1k/name1 -s 200 -x content-type=application/json -t '1k_name1' \
     -o /user1k/name2 -s 200 -x content-type=application/json -t '1k_name2' \
     -o /user1k/name3 -s 200 -x content-type=application/json -t '1k_name3' \
  -m POST -p /user4k/ -s 200 -x content-type=application/json -e 4k \
     -o /user4k/name1 -s 200 -x content-type=application/json -t '4k_name1' \
     -o /user4k/name2 -s 200 -x content-type=application/json -t '4k_name2' \
     -o /user4k/name3 -s 200 -x content-type=application/json -t '4k_name3' \
  -m POST -p /user10k/ -s 200 -x content-type=application/json -e 10k \
     -o /user10k/name1 -s 200 -x content-type=application/json -t '10k_name1' \
     -o /user10k/name2 -s 200 -x content-type=application/json -t '10k_name2' \
     -o /user10k/name3 -s 200 -x content-type=application/json -t '10k_name3'
```

client single uri GET case (default method is 'GET'):
```
./h2cli http://127.0.0.1:8080/user1k/nobody:
```

client single uri request with method and user header:
```
./h2cli -m POST -u http://127.0.0.1:8080/test.txt \
    -x content-type=application/json -f your_request_body_file
```

client single uri request with request symbol replacement on uri, hdr, body:
```
./h2cli -R __MDN__=01092%06d \
  -m POST -u http://127.0.0.1:8080/user/__MDN__  \
          -x content-type=application/json -t '{ "USER_MDN" : "__MDN__" }'
```

client multiple request senario:
```
./h2cli -R __MDN__=01092%06d -s http -a 127.0.0.1:8080 \
  -m POST   -p /user/__MDN__  \
            -x content-type=application/json -t '{ "USER_MDN" : "__MDN__" }'  \
  -m GET    -p /user/__MDN__  \
  -m DELETE -p /user/__MDN__
```

client loop case:
>   -P req_par for concurrent streams (max:100)
>   -C req_max for request loop count
>   -q suppress output for performance check
```
./h2cli -P 100 -C 100000 -m GET -u http://127.0.0.1:8080/user1k/nobody
```

# h2cli and h2svr Performance Tests

server for 1k/4k/10k performance test:
```
./h2svr -S http://0.0.0.0:8080 -S https://0.0.0.0:8081 \
  -m POST -p /user1k/ -s 200 -x content-type=application/json -e 1k \
  -m POST -p /user4k/ -s 200 -x content-type=application/json -e 4k \
  -m POST -p /user10k/ -s 200 -x content-type=application/json -e 10k \
  -q
```

client for tcp 1k/4k/10k  performance test:
```
./h2cli -P 100 -C 100000 -R __MDN__=01092%06d      \
  -m POST -u http://127.0.0.1:8080/user1k/__MDN__    \
          -x content-type=application/json -e 1k -q; \
./h2cli -P 100 -C 100000 -R __MDN__=01092%06d      \
  -m POST -u http://127.0.0.1:8080/user4k/__MDN__    \
          -x content-type=application/json -e 4k -q; \
./h2cli -P 100 -C 100000 -R __MDN__=01092%06d      \
  -m POST -u http://127.0.0.1:8080/user10k/__MDN__   \
          -x content-type=application/json -e 10k -q
```
--> TCP 1K/4K/10K TPS = 120K/80K/55K at Xeon Gold 6132 CPU @ 2.60GHz

client for tls 1k/4k/10k  performance test:
```
./h2cli -P 100 -C 100000 -R __MDN__=01092%06d      \
  -m POST -u https://127.0.0.1:8081/user1k/__MDN__   \
          -x content-type=application/json -e 1k -q; \
./h2cli -P 100 -C 100000 -R __MDN__=01092%06d      \
  -m POST -u https://127.0.0.1:8081/user4k/__MDN__   \
          -x content-type=application/json -e 4k -q; \
./h2cli -P 100 -C 100000 -R __MDN__=01092%06d      \
  -m POST -u https://127.0.0.1:8081/user10k/__MDN__  \
          -x content-type=application/json -e 10k -q
```
--> TLS 1K/4K/10K TPS = 55K/44K/33K at Xeon Gold 6132 CPU @ 2.60GHz


