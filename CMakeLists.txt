cmake_minimum_required (VERSION 3.1)

set(CMAKE_C_FLAGS "-g -Wall")

# http://stackoverflow.com/questions/10555706/
macro (add_executable _name)
  _add_executable(${ARGV})
  if (TARGET ${_name})
    target_link_libraries(${_name} err in_cksum dropnobody)
  endif()
endmacro()

add_library(err err.c)
add_library(in_cksum in_cksum.c)
add_library(dropnobody dropnobody.c myping.c)

add_executable(rawping rawping.c)
add_executable(spoofping spoofping.c)

install(TARGETS DESTINATION .)
