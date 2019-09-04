cmake_minimum_required(VERSION 3.11)
project(sniffer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/osdialog)

file(GLOB SRC "src/*.h" "src/*.hpp" "src/*.cpp")
file(GLOB IMGUI_SRC "imgui/*.h" "imgui/*.cpp")

find_package(SDL2 CONFIG REQUIRED)

add_definitions(-DSDL_MAIN_HANDLED)

add_library(imgui ${IMGUI_SRC})
target_link_libraries(imgui PRIVATE SDL2)

add_executable(${PROJECT_NAME} ${SRC})
target_link_libraries(${PROJECT_NAME} PRIVATE imgui osdialog)
if (WIN32)
	target_link_libraries(${PROJECT_NAME} PRIVATE wsock32 ws2_32)
endif()
