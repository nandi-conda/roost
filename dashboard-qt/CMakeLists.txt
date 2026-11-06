# Roost dashboard as a Qt Quick app, built for WebAssembly (see README.md).
cmake_minimum_required(VERSION 3.21)
project(roostdash LANGUAGES CXX)

find_package(Qt6 6.8 REQUIRED COMPONENTS Quick)
qt_standard_project_setup(REQUIRES 6.8)

qt_add_executable(roostdash main.cpp)
set_source_files_properties(Theme.qml PROPERTIES QT_QML_SINGLETON_TYPE TRUE)
qt_add_qml_module(roostdash
    URI Roost
    QML_FILES Main.qml Theme.qml Api.js
)
target_link_libraries(roostdash PRIVATE Qt6::Quick)

if(EMSCRIPTEN)
    # -Os keeps the module small enough for a Workers static asset (25 MiB cap).
    target_compile_options(roostdash PRIVATE -Os)
    target_link_options(roostdash PRIVATE -Os)
endif()
