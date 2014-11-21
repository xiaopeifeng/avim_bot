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

typedef struct avim_bot_ctx{
	const char *key_content;
	const char *cert_content;
	const char *bot_name;
}avim_bot_context_t;
	
int bot_init();

int bot_create();
int bot_setup();
int bot_remove();

int bot_stop();

#ifdef __cplusplus
}
#endif

#endif

