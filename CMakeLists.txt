cmake_minimum_required(VERSION 3.15...3.31)
project(node-win-hid)

add_compile_definitions(-DNAPI_VERSION=4)

file(GLOB SOURCE_FILES "${CMAKE_SOURCE_DIR}/addons/*")

add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES} ${CMAKE_JS_SRC})
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_JS_INC})
target_link_libraries(${PROJECT_NAME} PRIVATE ${CMAKE_JS_LIB})
if (WIN32)
  target_link_libraries(${PROJECT_NAME} PRIVATE setupapi hid cfgmgr32)
endif()
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_17)

if(MSVC AND CMAKE_JS_NODELIB_DEF AND CMAKE_JS_NODELIB_TARGET)
  # Generate node.lib
  execute_process(COMMAND ${CMAKE_AR} /def:${CMAKE_JS_NODELIB_DEF} /out:${CMAKE_JS_NODELIB_TARGET} ${CMAKE_STATIC_LINKER_FLAGS})
endif()

# Copy the built addon to the build directory, so we can require() without
# going into either [build/Release] or [build/Debug] directories.
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:${PROJECT_NAME}>
    ${CMAKE_SOURCE_DIR}/build/${PROJECT_NAME}.node
)
