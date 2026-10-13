cmake_minimum_required(VERSION 3.16)
project(phare C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(MSVC)
  add_compile_options(/W4)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

add_library(phare_http STATIC src/http.c)
target_include_directories(phare_http PUBLIC src)

add_executable(phare src/main.c src/fs.c)
target_link_libraries(phare PRIVATE phare_http)
if(WIN32)
  target_link_libraries(phare PRIVATE ws2_32)
else()
  find_package(Threads REQUIRED)
  target_link_libraries(phare PRIVATE Threads::Threads)
endif()

enable_testing()
add_executable(test_http tests/test_http.c)
target_link_libraries(test_http PRIVATE phare_http)
add_test(NAME http COMMAND test_http)
