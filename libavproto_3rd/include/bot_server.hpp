#pragma once

#include <unordered_map>
#include <boost/asio.hpp>
#include <boost/make_shared.hpp>
#include <boost/noncopyable.hpp>
#include <boost/thread.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/regex.hpp>
#include <boost/format.hpp>

#include "serialization.hpp"
#include "bot_group.hpp"
#include "bot_socket.hpp"
#include "bot_ca.hpp"

#include "message.pb.h"

namespace proto{
	class avpacket;
	class av_address;
}

inline proto::av_address av_address_from_string(std::string av_address)
{
    proto::av_address addr;
    boost::regex re("([^@]*)@([^/]*)(/(.*))?");
    boost::smatch m;
    if (boost::regex_search(av_address, m, re))
    {
        addr.set_username(m[1]);
        addr.set_domain(m[2]);
        if (m[3].matched)
        {
            addr.set_resource(m[4]);
        }
        return addr;
    }
	addr.set_domain("avplayer.org");
	addr.set_username(av_address);
    return addr;
}

inline std::string av_address_to_string(const proto::av_address & addr)
{
	if (addr.has_resource())
	{
		return boost::str( boost::format("%s@%s/%s") % addr.username() % addr.domain() % addr.resource());
	}
	return boost::str(boost::format("%s@%s") % addr.username() % addr.domain());
}

inline std::string i2d_X509(X509 * x509)
{
	unsigned char * out = NULL;
	int l = i2d_X509(x509, & out);
	std::string ret((char*)out, l);
	OPENSSL_free(out);
	return ret;
}


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
		void start();
		void stop();
		
		

		bool add_bot(const std::string& name, bot_role role);
		bool del_bot(const std::string& name);
		void dump_status();
		
		bool set_conn(std::string bot_addr,int bot_port,std::string server_addr,int server_port);
		bool set_role(bot_role role);
		
	private:
		bool server_login_start();
		bool handle_server_hello(google::protobuf::Message* msg);
		bool handle_login_result(google::protobuf::Message* msg);
		
	public:
		bool write_packet(const std::string &msg);
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
		bot_status m_status;
		
		boost::scoped_ptr<proto::av_address> m_local_addr;
		boost::scoped_ptr<proto::av_address> m_remote_addr;
		
		boost::shared_mutex m_server_mutex;
		typedef std::deque<std::string> msg_queue;
		msg_queue m_msg_queue;
		
		std::vector<bot_group_ptr> m_group_pool;
	};
	
}