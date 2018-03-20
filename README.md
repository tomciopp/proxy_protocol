## Proxy Protocol

A pure erlang parser for HAProxy's proxy protocol standard

## Warning

This library is still in flux.
It should not be considered stable until version 0.2.0 is released.

## Documentation

The official documentation for the protocol can be found at
https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt

## Usage

The proxy_protocol module has a single exported function `parse` which
will handle either v1 or v2 of the proxy protocol.

The code accepts a binary argument and returns a two item tuple with the first element
containing `ok` or `error` and the second containing a map with the following keys:

  body: The rest of the request (binary)

  header: Contains a record with the following schema

  ```
    {
      dest_address: (IPAddress tuple, or binary)
      dest_port: (Integer or undefined),
      inet: string in ["AF_UNIX", "TCP4", "TCP6", "UDP4", "UDP6", "UNKNOWN"],
      src_address: (IPAddress tuple, or Path binary),
      src_port (Integer or undefined),
      vsn: string in ["1", "2"]
    }
  ```

  message: (only for errors)
    The reason why there was an error
