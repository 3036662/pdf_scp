set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-invalid-utf8")

include_directories(/opt/cprocsp/include/pki /opt/cprocsp/include/cpcsp/ /opt/cprocsp/include/)

add_executable(1 1.cpp)

add_executable(1_no_link resolve_symbols.cpp 1_no_link.cpp)

target_link_directories(1 PRIVATE /opt/cprocsp/lib/amd64/)
target_link_libraries(1 capi20)
target_link_libraries(1 capi10)
target_link_libraries(1 cades)
target_link_libraries(1 rdrsup)