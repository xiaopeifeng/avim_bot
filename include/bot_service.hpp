#pragma once

#include <unordered_map>
#include <boost/noncopyable.hpp>
#include <boost/thread.hpp>
#include <boost/asio.hpp>

#include "avproto/serialization.hpp"
#include "packet.pb.h"

namespace bot_avim {
	
	// 0x0 - 0xFF - Common cmd
	const int CMD_STATE_CHANGED = 0x0;
	
	class bot_service
		: public boost::noncopyable
	{
	public:
		explicit bot_service(boost::asio::io_service& io_service, std::string &key, std::string &crt)
		: m_io_service(io_service)
		, m_key(key)
		, m_crt(crt)
		{};
		
		~bot_service(){};

	public:	
		virtual bool handle_message(int type, std::string sender, message::message_packet pkt){return true;};
		virtual bool notify(int cmd, int ext1 = 0, int ext2 = 0){return true;};
		
	private:		
		boost::asio::io_service& m_io_service;
		std::string m_key;
		std::string m_crt;
	};
	
}
