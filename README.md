# A small test to play wth OCSP app

OpenSSL ocsp app does not free socket property. If you need it for testing and
re-create the process again and again, you run into socket problems. OpenSSL 1.1.1 does not
seem to have the problem.

Typically something along these lines:

```
Error setting up accept BIO
4287:error:02006062:system library:bind:Address already in use:b_sock.c:659:port='2505'
4287:error:20069075:BIO routines:BIO_get_accept_socket:unable to bind socket:b_sock.c:661:
```
or
```
Error setting up accept BIO
140370159307480:error:02006062:system library:bind:Address already in use:b_sock.c:783:port='2504'
140370159307480:error:20069075:BIO routines:BIO_get_accept_socket:unable to bind socket:b_sock.c:785:
```

## Results

|                 | Result              |
|-----------------|---------------------|
| openssl-0.9.8zh | :red_circle:        |
| openssl-1.0.2p  | :red_circle:        |
| openssl-1.1.0i  | :large_blue_circle: |
| openssl-1.1.1   | :large_blue_circle: |
      