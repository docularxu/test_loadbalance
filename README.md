# test_loadbalance

1. To compile, run these:
```
mkdir build
cmake -S . -B build --log-level=DEBUG
cmake --build build --verbose
```

2. To launch the test, run:
```
./build/test_lbprov
OPENSSL_MODULES=/home/ubuntu/md5_mb_prov.git/build/src ./build/test_lbprov
```

Note: `OPENSSL_MODULES` points to paths where OSSL_PROVIDER_load() loads
custom providers from.

3. To config
This test supports both loading provider configuration from file and from code. Use this macro to select.
```
#define LOAD_FROM_CONF_FILE
```

