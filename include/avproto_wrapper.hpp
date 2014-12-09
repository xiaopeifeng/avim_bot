#pragma once

#include <unordered_map>
#include <boost/noncopyable.hpp>
#include <boost/thread.hpp>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>

#include "avproto/serialization.hpp"
#include "avproto.hpp"

#include "packet.pb.h"
#include "im.pb.h"

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
		: public boost::noncopyable
	{
	public:
		explicit avproto_wrapper(boost::asio::io_service& io_service, std::shared_ptr<RSA> key, std::shared_ptr<X509> crt);
		~avproto_wrapper();

	public:
		bool register_service(bot_service *service);
		bool start();
		const std::string& get_local_addr();

	public:
		void connect_coroutine(boost::asio::yield_context yield_context);
		bool login_coroutine(boost::asio::yield_context yield_context);
		bool handle_message(boost::asio::yield_context yield_context);
		bool write_packet(const std::string &target,const std::string &pkt);

	private:
		boost::asio::io_service& m_io_service;
		std::shared_ptr<RSA> m_key;
		std::shared_ptr<X509> m_crt;
		boost::shared_ptr<bot_service> m_service;
		
		std::shared_ptr<avjackif> m_avif;
		avkernel m_avkernel;
		std::string m_local_addr;
	};

}
