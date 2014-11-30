
add_executable(bot avim.cpp bot_group.cpp avproto_wrapper.cpp bot.cpp)

target_link_libraries(bot avproto++)
