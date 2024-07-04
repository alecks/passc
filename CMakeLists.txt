cmake_minimum_required(VERSION 3.28)
project(passc)

include(FetchContent)
include(FindSQLite3)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON) # for clangd

FetchContent_Declare(Sodium
    GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
    GIT_TAG 99f14233eab1d4f7f49c2af4ec836f2e701c445e # HEAD as of 2022-05-28
)
set(SODIUM_DISABLE_TESTS ON)
FetchContent_MakeAvailable(Sodium)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/lib/cwalk)

add_executable(${PROJECT_NAME} main.c)

target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(${PROJECT_NAME}
  PRIVATE sodium
  PRIVATE sqlite3
  PRIVATE cwalk)
