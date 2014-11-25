#include <boost/smart_ptr.hpp>
#include <boost/any.hpp>
#include <boost/asio.hpp>

#include "bot_server.hpp"
#include "bot_socket.hpp"
#include "logging.hpp"
#include <bot_ca.hpp>
#include "serialization.hpp"

namespace bot_avim {

	bot_socket::bot_socket(boost::asio::io_service& io, bot_server& serv)
		: m_io_service(io)
		, m_server(serv)
		, m_socket(io)
		, m_abort(false)
	{
	}

	bot_socket::~bot_socket()
	{
		LOG_DBG << "destruct bot_socket: " << this;
	}
	
	void bot_socket::set_bot_addr(std::string &addr, int port)
	{
		m_bot_addr = addr;
		m_bot_port = port;
	}
	
	void bot_socket::set_server_addr(std::string &addr, int port)
	{
		m_server_addr = addr;
		m_server_port = port;
	}

	void bot_socket::start()
	{
		LOG_DBG << "start the connection: " << this;
		
		boost::system::error_code ignore_ec;
		LOG_DBG << "connect to:" << m_server_addr << "port:" << m_server_port;
		
#if 0
		boost::asio::ip::tcp::endpoint endpoint(
		boost::asio::ip::address::from_string("127.0.0.1"), 24590);
		boost::system::error_code ec;
		m_socket.connect(endpoint, ec);
		if (ec)
		{
			// An error occurred.
			std::cout << ec.message() << std::endl;
		}
#endif
		boost::asio::ip::tcp::resolver resolver(m_io_service);
		auto resolved_host_iterator = resolver.resolve(boost::asio::ip::tcp::resolver::query("127.0.0.1", "24950"));
		boost::asio::connect(m_socket, resolved_host_iterator);


		m_response.consume(m_response.size());
		m_abort = false;

		m_socket.set_option(tcp::no_delay(true), ignore_ec);
		if (ignore_ec)
			LOG_ERR << "connection::start, Set option to nodelay, error message :" << ignore_ec.message();

		boost::asio::async_read(m_socket, m_response, boost::asio::transfer_exactly(4),
			boost::bind(&bot_socket::handle_read_header,
				shared_from_this(),
				boost::asio::placeholders::error,
				boost::asio::placeholders::bytes_transferred
			)
		);
	}

	void bot_socket::stop()
	{
		boost::system::error_code ignore_ec;
		m_abort = true;
		m_socket.close(ignore_ec);
	}

	tcp::socket& bot_socket::socket()
	{
		return m_socket;
	}

	void bot_socket::close()
	{
		
	}

	void bot_socket::handle_read_header(const boost::system::error_code& error, std::size_t bytes_transferred)
	{
		// 出错处理.
		if (error || m_abort)
		{
			close();
			return;
		}

		// 复制出来,避免影响m_response中接收到的数据, 也就4个字节.
		boost::asio::streambuf tempbuf;
		boost::asio::buffer_copy(tempbuf.prepare(m_response.size()), m_response.data());
		tempbuf.commit(m_response.size());

		// 获得包长度, 转为主机字节序.
		int packet_length = 0;
		tempbuf.sgetn(reinterpret_cast<char*>(&packet_length), sizeof(packet_length));
		packet_length = ntohl(packet_length);

		if (packet_length > 64 * 1024) // 过大的数据包, 此客户端有问题, 果然断开.
		{
			close();
			return;
		}

		// 继续读取packet_length长度的数据.
		boost::asio::async_read(m_socket, m_response, boost::asio::transfer_exactly(packet_length),
			boost::bind(&bot_socket::handle_read_body,
				shared_from_this(),
				boost::asio::placeholders::error,
				boost::asio::placeholders::bytes_transferred
			)
		);
	}

	void bot_socket::handle_read_body(const boost::system::error_code& error, std::size_t bytes_transferred)
	{
		// 出错处理.
		if (error || m_abort)
		{
			close();
			return;
		}

		// 读取到body并处理.
		int packet_length = static_cast<int>(bytes_transferred + 4);
		std::string message;
		message.resize(packet_length);
		m_response.sgetn(&message[0], packet_length);
		m_response.consume(packet_length);

		// 解析包.
		google::protobuf::Message* msg = decode(message);
		if (!msg)
		{
			close();
			return;
		}
		boost::scoped_ptr<google::protobuf::Message> defer(msg);

		LOG_DBG << this << " recv: " << msg->GetTypeName();

		// 处理这个消息.
		m_server.do_message(msg, shared_from_this());

		// 继续下一个消息头读取.
		boost::asio::async_read(m_socket, m_response, boost::asio::transfer_exactly(4),
			boost::bind(&bot_socket::handle_read_header,
				shared_from_this(),
				boost::asio::placeholders::error,
				boost::asio::placeholders::bytes_transferred
			)
		);

	}

	void bot_socket::handle_write(const boost::system::error_code& error)
	{
		if (!error)
		{
			m_write_queue.pop_front();
			if (!m_write_queue.empty())
			{
				boost::asio::async_write(m_socket,
					boost::asio::buffer(m_write_queue.front().data(),
					m_write_queue.front().length()),
					boost::bind(&bot_socket::handle_write,
					shared_from_this(),
					boost::asio::placeholders::error
					)
				);
			}
		}
		else
		{
			close();
		}
	}

	void bot_socket::write_msg(const std::string& msg)
	{
		m_io_service.post(boost::bind(&bot_socket::do_write, shared_from_this(), msg));
	}

	void bot_socket::do_write(std::string msg)
	{
		bool write_in_progress = !m_write_queue.empty();
		m_write_queue.push_back(msg);
		if (!write_in_progress)
		{
			boost::asio::async_write(m_socket,
				boost::asio::buffer(m_write_queue.front().data(),
				m_write_queue.front().length()),
				boost::bind(&bot_socket::handle_write,
				shared_from_this(),
				boost::asio::placeholders::error
				)
			);
		}
	}

}
