#pragma once

#include <unordered_map>
#include <boost/noncopyable.hpp>
#include <boost/thread.hpp>
#include <boost/asio.hpp>

#include "packet.pb.h"
#include "avproto/serialization.hpp"
#include "avproto_wrapper.hpp"

#include "bot_service.hpp"

namespace bot_avim {

	typedef enum
	{
		CLIENT_STATUS_OFFLINE  = 0,
		CLIENT_STATUS_ONLINE   = 1,
	}client_status;

	// CMD START FROM  0X100
	const int CMD_CLIENT_TEST = 0x100;

	class bot_client
		: public bot_service
	{
	public:
		explicit bot_client(boost::asio::io_service& io_service, std::shared_ptr<RSA> key, std::shared_ptr<X509> crt);
		~bot_client();

	public:
		bool handle_message(int type, std::string &sender, im_message pkt);
		bool handle_message(int type, std::string &sender, std::shared_ptr<google::protobuf::Message> msg_ptr);
		bool notify(int cmd, int ext1, int ext2);

	private:
		void notify(boost::system::error_code ec);

	private:
		client_status m_status;
		boost::shared_ptr<bot_avproto> m_avproto;
	};

}
