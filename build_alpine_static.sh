docker run --rm -v $(pwd):/src -w /src alpine:latest sh -c "apk add --no-cache g++ make musl-dev  openssl-dev openssl-libs-static && cd /src && make -f makefile_alpine_static"
