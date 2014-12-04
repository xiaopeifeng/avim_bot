
add_executable(bot bot_client.cpp bot_group.cpp avproto_wrapper.cpp main.cpp)

target_link_libraries(bot avim++)
