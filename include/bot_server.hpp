#pragma once

#include <unordered_map>
#include <boost/asio.hpp>
#include <boost/noncopyable.hpp>
#include <boost/thread.hpp>

#include "serialization.hpp"
#include "bot_group.hpp"
#include "bot_socket.hpp"
#include "bot_ca.hpp"

namespace bot_avim {

	typedef enum
	{
		BOT_ROLE_INVALID = -1,
		BOT_ROLE_CLIENT  = 0,
		BOT_ROLE_GROUP   = 1,
		BOT_ROLE_MAX     = 9,
	}bot_role;
	
	typedef enum
	{
		BOT_STATUS_OFFLINE   = 0,
		BOT_STATUS_LOGINING  = 1,
		BOT_STATUS_ONLINE    = 2,
	}bot_status;
	
	typedef boost::shared_ptr<boost::asio::io_service> io_service_ptr;
	typedef boost::shared_ptr<bot_group> bot_group_ptr;
	typedef boost::shared_ptr<bot_socket> bot_socket_ptr;
	
	class bot_server
		: public boost::noncopyable
	{
	public:
		explicit bot_server(boost::shared_ptr<RSA> rsa, boost::shared_ptr<X509> x509_cert);
		~bot_server();

	public:	
		void init();
		void start();
		void stop();

		bool add_bot(const std::string& name, bot_role role);
		bool del_bot(const std::string& name);
		void dump_status();
		
		bool set_conn(std::string bot_addr,int bot_port,std::string server_addr,int server_port);
		bool set_role(bot_role role);

	public:
		bool write_packet();
		bool do_message(google::protobuf::Message*, bot_socket_ptr);
		
	private:
		//group_init();
		//client_init();
		void continue_timer();
	
	private:
		bot_ca m_ca;
		
		io_service_ptr m_ios;
		bot_socket_ptr m_socket;
		std::string m_bot_addr;
		int m_bot_port;
		std::string m_server_addr;
		int m_server_por;
		
		bot_role m_role;
		bot_status status;
		
		typedef std::deque<std::string> msg_queue;
		msg_queue m_msg_queue;
		
		std::vector<bot_group_ptr> m_group_pool;
	};
	
}