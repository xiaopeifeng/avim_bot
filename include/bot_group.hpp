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
	
	typedef enum
	{
		GROUP_STATUS_OFFLINE  = 0,
		GROUP_STATUS_ONLINE   = 1,
	}group_status;
	
	class bot_group
		: public boost::noncopyable
	{
	public:
		explicit bot_group(boost::asio::io_service& io_service, std::string key, std::string crt);
		~bot_group();

	public:
		bool add_member(const std::string& name);
		bool del_member(const std::string& name);
		
		bool handle_message(int type, proto::avim_message_packet pkt);
		bool status_changed(int status);
		
		void dump_status();
		
	private:
		void notify(boost::system::error_code ec);
		
	private:		
		member_ptr m_group_member_list;
		boost::asio::io_service& m_io_service;
		group_status m_status;
		//avproto only
		boost::shared_ptr<avim_client> avim;
		avproto_wrapper m_avproto;
	};
	
}