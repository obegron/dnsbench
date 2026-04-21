cmake_minimum_required(VERSION 3.24)

project(DnsBenchmark
    VERSION 0.1.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Network Gui Widgets Charts Test)
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json CONFIG QUIET)

qt_standard_project_setup()

set(DNSBENCH_CORE_SOURCES
    src/model/ResolverModel.cpp
    src/benchmark/DnsPacket.cpp
    src/benchmark/Statistics.cpp
)

add_library(dnsbench_core STATIC ${DNSBENCH_CORE_SOURCES})
target_include_directories(dnsbench_core PUBLIC src)
target_link_libraries(dnsbench_core
    PUBLIC
        Qt6::Core
        Qt6::Network
        Qt6::Gui
        OpenSSL::SSL
        OpenSSL::Crypto
)

if(nlohmann_json_FOUND)
    target_link_libraries(dnsbench_core PUBLIC nlohmann_json::nlohmann_json)
    target_compile_definitions(dnsbench_core PUBLIC DNSBENCH_HAS_NLOHMANN_JSON=1)
endif()

set(DNSBENCH_APP_SOURCES
    src/main.cpp
    resources/resources.qrc
    src/ui/AddResolverDialog.cpp
    src/ui/MainWindow.cpp
    src/ui/ResultsTab.cpp
    src/benchmark/BenchmarkController.cpp
    src/benchmark/DohResolver.cpp
    src/benchmark/DotResolver.cpp
    src/benchmark/UdpResolver.cpp
    src/detection/LinuxDnsDetector.cpp
    src/detection/SystemDnsDetector.cpp
    src/export/ResultExporter.cpp
)

qt_add_executable(dnsbench ${DNSBENCH_APP_SOURCES})
target_include_directories(dnsbench PRIVATE src)
target_link_libraries(dnsbench
    PRIVATE
        dnsbench_core
        Qt6::Core
        Qt6::Network
        Qt6::Widgets
        Qt6::Charts
        OpenSSL::SSL
        OpenSSL::Crypto
)

install(TARGETS dnsbench
    BUNDLE DESTINATION .
    RUNTIME DESTINATION bin
)

enable_testing()

qt_add_executable(test_statistics tests/test_statistics.cpp)
target_link_libraries(test_statistics PRIVATE dnsbench_core Qt6::Test)
add_test(NAME test_statistics COMMAND test_statistics)

qt_add_executable(test_dns_packet tests/test_dns_packet.cpp)
target_link_libraries(test_dns_packet PRIVATE dnsbench_core Qt6::Test)
add_test(NAME test_dns_packet COMMAND test_dns_packet)

qt_add_executable(test_dns_detection
    tests/test_dns_detection.cpp
    src/detection/LinuxDnsDetector.cpp
)
target_include_directories(test_dns_detection PRIVATE src)
target_link_libraries(test_dns_detection PRIVATE dnsbench_core Qt6::Test)
add_test(NAME test_dns_detection COMMAND test_dns_detection)
