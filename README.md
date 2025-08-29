[![vibe.d](https://vibed.org/images/title-new.png)](https://vibed.org)

vibe.d advanced stream types and TLS support
============================================

This package contains a number of advanced stream types, including TLS server and client support.

### OpenSSL Auto key logging

If the version `VibeKeylogFromEnvironment` is specified as a build parameter, and the feature is supported (requires openssl version 1.1.1 or later), then the library will examine the environment variable `SSLKEYLOGFILE` for a path to write all keys to.

This is handy for use with the wireshark tool for inspecting traffic. See for instance how [cURL](https://everything.curl.dev/usingcurl/tls/sslkeylogfile.html) does this.
