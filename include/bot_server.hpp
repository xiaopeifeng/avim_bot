#pragma once

#include <unordered_map>
#include <boost/asio.hpp>
#include <boost/noncopyable.hpp>
#include <boost/thread.hpp>

#include "bot_group.hpp"
#include "bot_ca.hpp"

extern std::pair< iterator, iterator > r;
namespace bot_avim {

	typedef enum
	{
		BOT_TYPE_CLIENT= 0,
		BOT_TYPE_GROUP = 1,
		BOT_TYPE_MAX   = 9,
	}bot_role;
	
	class bot_server
		: public boost::noncopyable
	{
	public:
		explicit bot_server(boost::shared_ptr<RSA> rsa, boost::shared_ptr<X509> x509_cert, bot_role role);
		~bot_server();

	public:	
		void start();
		void stop();

		bool add_bot(const std::string& name, bot_role role);
		bool del_bot(const std::string& name);
		void dump_status();

	public:
		bool write_packet();
		bool handle_packet();
		
	private:
		//group_init();
		//client_init();
		void continue_timer();
	
	private:
		typedef boost::shared_ptr<boost::asio::io_service> io_service_ptr;
		typedef boost::shared_ptr<bot_group> bot_group_ptr;
		
		io_service_ptr m_ios;
		bot_ca m_ca;
		bot_role m_role;
		
		std::string m_bot_addr;
		int m_bot_port;
		std::string m_router_addr;
		int m_router_port;
		typedef std::deque<std::string> msg_queue;
		msg_queue m_msg_queue;
		
		std::vector<bot_group_ptr> m_group_pool;
	};
	
}