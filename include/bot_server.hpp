#pragma once

#include <unordered_map>
#include <boost/noncopyable.hpp>
#include <boost/thread.hpp>

#include "bot_group.hpp"

namespace bot_avim {

	enum bot_type
	{
		BOT_TYPE_GROUP = 0,
		BOT_TYPE_MAX   = 9,
	};
	
	class bot_server
		: public boost::noncopyable
	{
	public:
		explicit bot_server();
		~bot_server();

	public:	
		void start();
		void stop();

		bool add_bot(const std::string& name, bot_type type);
		bool del_bot(const std::string& name);
		void dump_status();

	private:
		void continue_timer();
		
	};
	
}