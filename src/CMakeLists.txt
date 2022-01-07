include_directories(.)

add_executable(
  sec_num_main

  sec_num_main.cpp
)
target_link_libraries(
  sec_num_main

  snark
)
target_include_directories(
  sec_num_main

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)

add_executable(
  timestamp_main

  timestamp_main.cpp
)
target_link_libraries(
  timestamp_main

  snark
)
target_include_directories(
  timestamp_main

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)