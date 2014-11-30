#pragma once

#include <unordered_map>
#include <boost/noncopyable.hpp>
#include <boost/thread.hpp>
#include <boost/asio.hpp>

#include "message.pb.h"
#include "serialization.hpp"
#include "avim.hpp"
#include "message.pb.h"
#include "avproto_wrapper.hpp"

namespace bot_avim {

	typedef std::vector<std::string> member_ptr;
	
	class bot_group
		: public boost::noncopyable
	{
	public:
		explicit bot_group(boost::asio::io_service& io_service, std::string key, std::string crt);
		~bot_group();

	public:
		bool add_member(const std::string& name);
		bool del_member(const std::string& name);
		
		bool handle_message(int type, std::string msg);
		
		void dump_status();
		
	private:
		void notify(boost::system::error_code ec);
		
	private:		
		member_ptr m_group_member_list;
		boost::asio::io_service& m_io_service;
		
		//avproto only
		boost::shared_ptr<avim_client> avim;
		avproto_wrapper m_avproto;
	};
	
}