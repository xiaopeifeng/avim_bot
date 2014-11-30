
add_executable(bot bot_group.cpp avproto_wrapper.cpp bot.cpp)

target_link_libraries(bot avproto++)
