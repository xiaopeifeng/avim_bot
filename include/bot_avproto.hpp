#pragma once

#include <unordered_map>
#include <boost/noncopyable.hpp>
#include <boost/thread.hpp>
#include <boost/asio.hpp>

#include "avproto/serialization.hpp"
#include "packet.pb.h"
#include "im.pb.h"

namespace bot_avim {
	
	class bot_service;
	
	class bot_avproto
		: public boost::noncopyable
	{
	public:
		explicit bot_avproto(boost::asio::io_service& io_service, std::string &key, std::string &crt)
		: m_io_service(io_service)
		, m_key(key)
		, m_crt(crt)
		{};
		
		~bot_avproto(){};

	public:
		virtual bool register_service(bot_service *service){m_service.reset(service); return true;};
		virtual bool start(){return true;};
		virtual bool write_packet(std::string target, std::string &pkt){return true;};
		
	protected:		
		boost::asio::io_service& m_io_service;
		std::string m_key;
		std::string m_crt;
		boost::shared_ptr<bot_service> m_service;
	};
	
}
