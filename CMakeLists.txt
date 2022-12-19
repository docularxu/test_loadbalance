cmake_minimum_required(VERSION 3.12 FATAL_ERROR)
project(
  test-lbprov
  VERSION 0.1
  DESCRIPTION "A demonstration of the load balancing provider usage"
  LANGUAGES C)
set(CMAKE_C_STANDARD 99)

set(OPENSSL_CRYPTO_LIBRARY "/usr/local/lib/libcrypto.so.3")
set(OPENSSL_CRYPTO_LIBRARIES "/usr/local/lib/libcrypto.so.3")
set(OPENSSL_INCLUDE_DIR "/usr/local/include")
MESSAGE("OPENSSL_CRYPTO_LIBRARY=${OPENSSL_CRYPTO_LIBRARY}")
MESSAGE("OPENSSL_CRYPTO_LIBRARIES=${OPENSSL_CRYPTO_LIBRARIES}")
MESSAGE("OPENSSL_INCLUDE_DIR=${OPENSSL_INCLUDE_DIR}")

add_executable(test_lbprov test_lb.c)
target_include_directories(test_lbprov PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_libraries(test_lbprov
  PRIVATE ${OPENSSL_CRYPTO_LIBRARIES}
	  pthread
          )
