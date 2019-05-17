project(test_rsa_sha)
add_executable(main test_rsa_sha.c)
target_link_libraries(main crypto)
