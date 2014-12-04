#pragma once

#include <unordered_map>
#include <boost/noncopyable.hpp>
#include <boost/thread.hpp>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>

#include "avproto/serialization.hpp"
#include "packet.pb.h"

#include "bot_avproto.hpp"
#include "avproto.hpp"

class avjackif;
class avkernel;

namespace bot_avim {
	
	class bot_service;
	
	enum msg_type
	{
		MESSAGE_TEXT  = 0,
		MESSAGE_IMAGE = 1,
		MESSAGE_VIDEO = 2,
		MESSAGE_CMD   = 3
	};
	
	class avproto_wrapper
		: public bot_avproto
	{
	public:
		explicit avproto_wrapper(boost::asio::io_service& io_service, std::string key, std::string crt);
		~avproto_wrapper();

	public:
		virtual bool register_service(bot_service *service);
		virtual bool start();
		virtual bool write_msg(std::string target, message::message_packet &pkt);
		
	public:
		void connect_coroutine(boost::asio::yield_context yield_context);
		bool login_coroutine(boost::asio::yield_context yield_context);
		bool handle_message(boost::asio::yield_context yield_context);
	
	private:
		std::shared_ptr<avjackif> m_avif;
		avkernel m_avkernel;
	};
	
}
