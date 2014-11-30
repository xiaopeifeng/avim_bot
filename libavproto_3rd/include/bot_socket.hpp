#pragma once

#include <set>
#include <deque>

#include <boost/noncopyable.hpp>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
using boost::asio::ip::tcp;
#include <boost/date_time.hpp>
using namespace boost::posix_time;

#include "logging.hpp"

namespace bot_avim {
	
	class bot_server;
	
	class bot_socket
		: public boost::enable_shared_from_this<bot_socket>
		, public boost::noncopyable
	{
	public:
		explicit bot_socket(boost::asio::io_service& io, bot_server& serv);
		~bot_socket();

	public:
		void start();
		void stop();
		
		void set_bot_addr(std::string &addr, int port);
		void set_server_addr(std::string &addr, int port);

		tcp::socket& socket();
		void write_msg(const std::string& msg);

	private:
		void close();

		void handle_read_header(const boost::system::error_code& error, std::size_t bytes_transferred);
		void handle_read_body(const boost::system::error_code& error, std::size_t bytes_transferred);
		
		void handle_write(const boost::system::error_code& error);
		void do_write(std::string msg);

	private:
		boost::asio::io_service &m_io_service;
		bot_server &m_server;
		
		tcp::socket m_socket;
		std::string m_bot_addr;
		int m_bot_port;
		std::string m_server_addr;
		int m_server_port;
		
		boost::asio::streambuf m_request;
		boost::asio::streambuf m_response;
		typedef std::deque<std::string> write_queue;
		write_queue m_write_queue;
		bool m_abort;
	};
}
