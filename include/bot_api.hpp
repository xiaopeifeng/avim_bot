/*
 * bot_api.hpp
 * 
 */

#ifndef BOT_API_H
#define BOT_API_H

#ifdef __cplusplus
extern "C" {
#endif

int bot_init();
int bot_send_message();
int bot_recv_message();
int bot_stop();

#ifdef __cplusplus
}
#endif

#endif

