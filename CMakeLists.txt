cmake_minimum_required(VERSION 3.10)

project(Sensor_local_client VERSION 1.0)

set ( PROJECT_LINK_LIBS libcoap-3-openssl.so )
link_directories( /usr/local/lib )

include_directories(includes)

file(GLOB SOURCES "src/*.c")

add_executable(local_client ${SOURCES})

target_link_libraries(local_client m pthread ${PROJECT_LINK_LIBS})