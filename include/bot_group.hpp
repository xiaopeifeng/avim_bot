#pragma once

#include <unordered_map>
#include <boost/noncopyable.hpp>
#include <boost/thread.hpp>

#include "message.pb.h"
#include "serialization.hpp"

namespace bot_avim {

	typedef std::vector<std::string> member_ptr;
	class bot_server;
	
	class bot_group
		: public boost::noncopyable
	{
	public:
		explicit bot_group(bot_server& serv);
		~bot_group();

	public:
		bool add_member(const std::string& name);
		bool del_member(const std::string& name);
		
		bool handle_message(google::protobuf::Message* msg);
		
		void dump_status();
		
	private:		
		member_ptr m_group_member_list;
		bot_server &m_server;
		
	};
	
}