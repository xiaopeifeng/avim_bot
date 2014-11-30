#pragma once

#include <unordered_map>
#include <boost/noncopyable.hpp>
#include <boost/thread.hpp>
#include <boost/asio.hpp>

#include "message.pb.h"
#include "serialization.hpp"
#include "avim.hpp"
#include "message.pb.h"

class avjackif;
class avkernel;

namespace bot_avim {
	
	class bot_group;
	
	enum msg_type
	{
		MESSAGE_TEXT  = 0,
		MESSAGE_IMAGE = 1,
		MESSAGE_VIDEO = 2,
		MESSAGE_CMD   = 3
	};
	
	class avproto_wrapper
		: public boost::noncopyable
	{
	public:
		explicit avproto_wrapper(boost::asio::io_service& io_service, std::string key, std::string crt);
		~avproto_wrapper();

	public:
		bool register_service(bot_group *group);
		void connect_coroutine(boost::asio::yield_context yield_context);
		bool start();
		bool login(boost::asio::yield_context yield_context);
		bool handle_message();
		
	private:		
		boost::asio::io_service& m_io_service;
		std::string m_key;
		std::string m_crt;
		boost::shared_ptr<bot_group> m_service;
		std::shared_ptr<boost::asio::ip::tcp::socket> m_socket;
		std::shared_ptr<avjackif> m_avif;
	};
	
}