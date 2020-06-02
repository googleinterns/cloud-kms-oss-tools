# Minimum Useless Engine

A "minimum useless engine" for OpenSSL based on [this tutorial][tutorial].

## Usage

From within the `mue` directory:

```bash
bazel build engine
openssl engine -t -c `pwd`/../bazel-bin/mue/libengine.so
```

[tutorial]: https://www.openssl.org/blog/blog/2015/10/08/engine-building-lesson-1-a-minimum-useless-engine/
