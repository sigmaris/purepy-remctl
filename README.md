purepy-remctl
=============

This is a pure Python implementation of a [remctl](http://www.eyrie.org/~eagle/software/remctl/)
protocol version 3 client. The interface mostly follows the
[Python C binding](http://www.eyrie.org/~eagle/software/remctl/python-readme.html) which is
packaged with the original remctl software distribution, with a few exceptions:

* There is no `Remctl.set_ccache(ccache)` method, there is a `Remctl.set_credential(credential)`
  method instead. `set_credential()` accepts an (initiator) `gssapi.Credential` object from the
  [python-gssapi](https://github.com/sigmaris/python-gssapi) package, which will be used as a
  credential to initiate the GSSAPI security context with the remctl server. This allows using, for
  example, a delegated credential to perform remctl operations without needing to store the
  delegated credential in a credential cache.
* There is no `_remctl` module providing a low-level wrapper of the C API.
* There is no support for the remctl protocol version 1. Only version >= 2 servers are supported.

The motivation for writing this module instead of using the existing Python bindings to the remctl
C client library was:

* To be able to use delegated credentials obtained from the python-gssapi package in an
  application to perform remctl operations.
* To avoid performing blocking socket operations in the C library, so that remctl operations can be
  performed in an application using [gevent](http://gevent.org) without blocking (if the `socket`
  module is patched by gevent)

This project is licensed under the terms of the MIT license (see LICENSE.txt).
