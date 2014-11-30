
add_executable(bot bot_group.cpp avproto_wrapper.cpp main.cpp)

target_link_libraries(bot avproto++)
