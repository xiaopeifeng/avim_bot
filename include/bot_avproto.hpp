#pragma once

#include <unordered_map>
#include <boost/noncopyable.hpp>
#include <boost/thread.hpp>
#include <boost/asio.hpp>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "avproto/serialization.hpp"
#include "packet.pb.h"
#include "im.pb.h"

namespace bot_avim {

	class bot_service;

	class bot_avproto
		: public boost::noncopyable
	{
	public:
		explicit bot_avproto(boost::asio::io_service& io_service, std::shared_ptr<RSA> key, std::shared_ptr<X509> crt)
		: m_io_service(io_service)
		, m_key(key)
		, m_crt(crt)
		{};

		~bot_avproto(){};

	public:
		virtual bool register_service(bot_service *service){return true;};
		virtual bool start(){return true;};
		virtual bool write_packet(const std::string& target, const std::string &pkt){return true;};

	protected:
		boost::asio::io_service& m_io_service;
		std::shared_ptr<RSA> m_key;
		std::shared_ptr<X509> m_crt;
		boost::shared_ptr<bot_service> m_service;
	};

}
