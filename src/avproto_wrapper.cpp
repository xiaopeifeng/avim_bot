#include "logging.hpp"
#include "avproto_wrapper.hpp"
#include "bot_group.hpp"

#include "avproto.hpp"
#include "avjackif.hpp"

namespace bot_avim {

	avproto_wrapper::avproto_wrapper(boost::asio::io_service& io_service, std::string key, std::string crt)
	: m_io_service(io_service)
	, m_key(key)
	, m_crt(crt)
	{
		LOG_DBG << "bot group constructor";
	}

	avproto_wrapper::~avproto_wrapper()
	{}
	
	bool avproto_wrapper::register_service(bot_group *group)
	{
		m_service.reset(group);
	}
	
	void avproto_wrapper::connect_coroutine(boost::asio::yield_context yield_context)
	{
		boost::system::error_code ec;
		using namespace boost::asio::ip;

		tcp::resolver resolver(m_io_service);

		auto _debug_host = getenv("AVIM_HOST");
		tcp::resolver::query query(_debug_host?_debug_host:"avim.avplayer.org", "24950");

		auto endpoint_iterator = resolver.async_resolve(query, yield_context[ec]);

		if (ec || endpoint_iterator == tcp::resolver::iterator())
		{
			std::cout << "server not found" << std::endl;
			return;
		}

		m_socket.reset(new tcp::socket(m_io_service));

		boost::asio::async_connect(*m_socket, endpoint_iterator, yield_context[ec]);

		if (ec)
		{
			std::cout << "connection failed, msg: " << ec.message() << std::endl;
			return;
		}
		std::cout << "connection established " << std::endl;
	}
	
	bool avproto_wrapper::start()
	{
		boost::asio::spawn(m_io_service, std::bind(&avproto_wrapper::connect_coroutine, this, std::placeholders::_1));
		m_avif.reset(new avjackif(m_socket));
		boost::asio::spawn(m_io_service, std::bind(&avproto_wrapper::login, this, std::placeholders::_1));
	}
	
	bool avproto_wrapper::login(boost::asio::yield_context yield_context)
	{
		m_avif->set_pki(m_key, m_crt);
		if (m_avif->async_handshake(yield_context))
		{
			std::cout << "login success " << std::endl;
		}
		return true;
	}
	
	bool avproto_wrapper::handle_message()
	{
		return true;
	}
}
