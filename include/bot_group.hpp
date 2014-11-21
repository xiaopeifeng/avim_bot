#pragma once

#include <unordered_map>
#include <boost/noncopyable.hpp>
#include <boost/thread.hpp>

namespace bot_avim {

	class bot_group
		: public boost::noncopyable
	{
	public:
		explicit bot_group();
		~bot_group();

	public:	
		void start();
		void stop();

		bool add_member(const std::string& name);
		bool del_member(const std::string& name);
		
		void dump_status();
	};
	
}