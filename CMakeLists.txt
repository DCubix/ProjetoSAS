cmake_minimum_required(VERSION 3.11)
project(sniffer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-DSDL_MAIN_HANDLED)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/osdialog)

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}/osdialog
)

file(GLOB SRC "src/*.h" "src/*.hpp" "src/*.cpp")
file(GLOB IMGUI_SRC "imgui/*.h" "imgui/*.cpp")

find_package(SDL2 CONFIG REQUIRED)
find_package(PCAP REQUIRED)

include_directories(${PCAP_INCLUDE_DIR})

add_library(imgui ${IMGUI_SRC})
target_link_libraries(imgui PRIVATE SDL2)

add_executable(${PROJECT_NAME} ${SRC})
target_link_libraries(${PROJECT_NAME} PRIVATE imgui osdialog ${PCAP_LIBRARY})

if (WIN32)
	target_link_libraries(${PROJECT_NAME} PRIVATE wsock32 ws2_32 iphlpapi)
elseif (UNIX)
	target_link_libraries(${PROJECT_NAME} PRIVATE pthread)
	if (CMAKE_DL_LIBS)
		target_link_libraries(${PROJECT_NAME} PRIVATE ${CMAKE_DL_LIBS})
	endif()
endif()