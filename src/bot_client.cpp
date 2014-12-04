#include "logging.hpp"
#include "bot_client.hpp"

namespace bot_avim {

	bot_client::bot_client(boost::asio::io_service& io_service, std::string key, std::string crt)
	: bot_service(io_service, key, crt)
	, m_status(CLIENT_STATUS_OFFLINE)
	{	
		m_avproto.reset(new avproto_wrapper(io_service, key, crt));
		
		m_avproto.get()->register_service(this);
		m_avproto.get()->start();
		
		LOG_DBG << "bot client constructor";
	}

	bot_client::~bot_client()
	{}

	bool bot_client::notify(int cmd, int ext1, int ext2)
	{
		if(cmd == CMD_STATE_CHANGED)
		{
			m_status = static_cast<client_status>(ext1);
			if(m_status == CLIENT_STATUS_ONLINE)
			{
				// send test pkt
				message::message_packet pkt;
				pkt.mutable_avim()->Add()->mutable_item_text()->set_text("test");
				m_avproto.get()->write_msg("group@avplayer.org", pkt);
				return true;
			}
		}
	}
	
	bool bot_client::handle_message(int type, std::string &sender, im_message msgpkt)
	{
		std::cout << "get pkt" << std::endl;
		
		if(msgpkt.is_message == 0)
		{
			return false;
		}
		
		
		for (message::avim_message im_message_item : msgpkt.impkt.avim())
		{
			if (im_message_item.has_item_text())
			{
				std::cerr << im_message_item.item_text().text() << std::endl;
			}
		}
		
		return true;
	}
	
}
