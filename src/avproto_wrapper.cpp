#include "logging.hpp"
#include "avproto_wrapper.hpp"
#include "bot_group.hpp"

#include "avproto.hpp"
#include "avjackif.hpp"
#include "message.hpp"

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

namespace bot_avim {

	avproto_wrapper::avproto_wrapper(boost::asio::io_service& io_service, std::string key, std::string crt)
	: m_io_service(io_service)
	, m_key(key)
	, m_crt(crt)
	, m_avkernel(io_service)
	{
		LOG_DBG << "bot group constructor";
	}

	avproto_wrapper::~avproto_wrapper()
	{}
	
	bool avproto_wrapper::register_service(bot_group *group)
	{
		m_service.reset(group);
	}
	
	bool avproto_wrapper::start()
	{
		boost::asio::spawn(m_io_service, std::bind(&avproto_wrapper::connect_coroutine, this, std::placeholders::_1));
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
		m_avif.reset(new avjackif(m_socket));
		boost::asio::spawn(m_io_service, std::bind(&avproto_wrapper::login, this, std::placeholders::_1));
	}
	
	bool avproto_wrapper::login(boost::asio::yield_context yield_context)
	{
		boost::shared_ptr<BIO> keyfile(BIO_new_mem_buf(&m_key[0], m_key.length()), BIO_free);
		boost::shared_ptr<BIO> certfile(BIO_new_mem_buf(&m_crt[0], m_crt.length()), BIO_free);

		std::shared_ptr<RSA> m_rsa_key;
		std::shared_ptr<X509> m_x509_cert;
		m_rsa_key.reset(
		PEM_read_bio_RSAPrivateKey(keyfile.get(), 0, 0, 0), //(pem_password_cb*)pass_cb,(void*) key.c_str()),
		RSA_free
		);

		m_x509_cert.reset(PEM_read_bio_X509(certfile.get(), 0, 0, 0), X509_free);
		
		m_avif->set_pki(m_rsa_key, m_x509_cert);
		if (m_avif->async_handshake(yield_context))
		{
			std::cout << "login success " << std::endl;
		}
		
		// start message_receiver
		boost::asio::spawn(m_io_service, std::bind(&avproto_wrapper::handle_message, this, std::placeholders::_1));
		
		m_service.get()->status_changed(1);
		return true;
	}
	
	bool avproto_wrapper::handle_message(boost::asio::yield_context yield_context)
	{
		for(;;)
		{
			std::string target,data;
			m_avkernel.async_recvfrom(target, data, yield_context);
			m_service.get()->handle_message(0, decode_message(data));
		}
		return true;
	}
	
	bool avproto_wrapper::write_msg(std::string target, proto::avim_message_packet &pkt)
	{
		m_avkernel.async_sendto(target, encode_message(pkt), [](boost::system::error_code ec){
			std::cout << "send ok" << std::endl;
		});
	}
	
}
