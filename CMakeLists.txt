cmake_minimum_required(VERSION 3.0)

project(ThreatScraper)

# nlohmann_json
find_path(NLOHMANN_JSON_INCLUDE_DIRS NAMES nlohmann/json.hpp)
find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
  message(STATUS "nlohmann_json not found, using the one from vcpkg")
  include_directories(${NLOHMANN_JSON_INCLUDE_DIRS})
endif()

# CURL
find_package(CURL REQUIRED)

# Qt5
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)
find_package(Qt5 COMPONENTS Widgets REQUIRED)

# Add the following lines to find the XLNT package
# set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
find_package(XLNT REQUIRED)

add_executable(${PROJECT_NAME} ThreatScraper.cpp)

# Add XLNT::xlnt to the target_link_libraries command
target_link_libraries(${PROJECT_NAME} PRIVATE nlohmann_json::nlohmann_json CURL::libcurl Qt5::Widgets xlnt)