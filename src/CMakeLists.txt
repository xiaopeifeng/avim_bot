
add_executable(avim-group-bot bot_client.cpp bot_group.cpp avproto_wrapper.cpp main.cpp)

target_link_libraries(avim-group-bot avim++)
