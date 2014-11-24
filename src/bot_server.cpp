#include "logging.hpp"
#include "bot_server.hpp"

namespace bot_avim {

	bot_server::bot_server(boost::shared_ptr<RSA> rsa, boost::shared_ptr<X509> x509_cert)
	: m_ca(rsa, x509_cert)
	{
		status = BOT_STATUS_OFFLINE;
		m_role = BOT_ROLE_INVALID;
		m_ios.reset(new boost::asio::io_service);
		LOG_DBG << "bot server constructor";
	}

	bot_server::~bot_server()
	{}
	
	bool bot_server::set_conn(std::string bot_addr,int bot_port,std::string server_addr,int server_port)
	{
		m_bot_addr = bot_addr;
		m_bot_port = bot_port;
		m_server_addr = server_addr;
		m_server_por = server_port;
		
		LOG_DBG << "bot addr:" << bot_addr;
		LOG_DBG << "bot port:" << bot_port;
		LOG_DBG << "server addr:" << server_addr;
		LOG_DBG << "server port:" << server_port;
		return true;
	}
	
	bool bot_server::set_role(bot_role role)
	{
		m_role = role;
		LOG_DBG << "ROLE:" <<role;
		return true;
	}
	
	void bot_server::start()
	{
		m_socket.reset(new bot_socket(boost::ref(*m_ios), boost::ref(*this)));
		//m_socket = boost::make_shared<bot_socket>(boost::ref(*m_ios), boost::ref(*this));
		m_socket.get()->set_bot_addr(m_bot_addr, m_bot_port);
		m_socket.get()->set_server_addr(m_server_addr, m_server_por);
		m_socket.get()->start();
		m_ios->run();
	}

	void bot_server::stop()
	{
		m_ios->stop();
	}

	bool bot_server::write_packet()
	{
	}
	
	bool bot_server::do_message(google::protobuf::Message*, bot_socket_ptr)
	{
		return true;
	}
	
	bool bot_server::add_bot(const std::string& name, bot_role type)
	{
		return true;
	}

	bool bot_server::del_bot(const std::string& name)
	{
		return true;
	}

	void bot_server::continue_timer()
	{
	}
	
	void bot_server::dump_status()
	{
	}
	
}
