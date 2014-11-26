
set(SRC bot_api.cpp bot_group.cpp bot_server.cpp bot_ca.cpp bot_socket.cpp message.cpp server_bot.cpp)

#add_library(bot_avim STATIC ${HDRS} ${SRCS})

add_executable(bot ${SRC})

target_link_libraries(bot avimproto)