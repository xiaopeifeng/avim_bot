/*
 * bot_api.hpp
 * 
 */

#ifndef BOT_API_H
#define BOT_API_H

#ifdef __cplusplus
#include <boost/iterator/iterator_concepts.hpp>
extern "C" {
#endif

typedef int (*bot_cb)(int type, char *msg);
	
typedef struct{
	char *key_path;
	char *cert_path;
	int role;
	const char *bot_name;
}bot_context_t;
	
int bot_init(bot_context_t *ctx);
int bot_reg_cb(bot_cb cb);
int bot_create();
int bot_setup();
int bot_remove();

int bot_stop();

#ifdef __cplusplus
}
#endif

#endif

