#pragma once

#include <unordered_map>
#include <boost/noncopyable.hpp>
#include <boost/thread.hpp>

#include "bot_group.hpp"
#include "bot_ca.hpp"

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

	private:
		//group_init();
		//client_init();
		void continue_timer();
	
	private:
		bot_ca m_ca;
		std::string m_server_key;
		std::string m_server_cert;
		bot_role m_role;
	};
	
}