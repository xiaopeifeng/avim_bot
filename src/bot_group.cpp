#include "logging.hpp"
#include "bot_group.hpp"

namespace bot_avim {

	bot_group::bot_group(boost::asio::io_service& io_service, std::string key, std::string crt)
	: m_io_service(io_service)
	, m_avproto(m_io_service, key, crt)
	, m_status(GROUP_STATUS_OFFLINE)
	{
		// tmp op - add member
		add_member("hyq@avplayer.org");
		add_member("luofei@avplayer.org");
		add_member("michael.fan@avplayer.org");
		add_member("microcai@avplayer.org");
		add_member("mrshelly@avplayer.org");
		add_member("xosdy@avplayer.org");
		add_member("zxf@avplayer.org");
		add_member("peter@avplayer.org");
		add_member("test-client@avplayer.org");
		
		m_avproto.register_service(this);
		m_avproto.start();
		
		LOG_DBG << "bot group constructor";
	}

	bot_group::~bot_group()
	{}

	bool bot_group::status_changed(int status)
	{
		m_status = static_cast<group_status>(status);
		
		if(m_status == GROUP_STATUS_ONLINE)
		{
			// send test pkt
			proto::avim_message_packet pkt;
			pkt.mutable_avim()->Add()->mutable_item_text()->set_text("test");
			m_avproto.write_msg("test-client@avplayer.org", pkt);
		}
	}
	
	bool bot_group::add_member(const std::string& name)
	{
		m_group_member_list.push_back(name);
		LOG_DBG << "insert group member: " << name;
		return true;
	}

	bool bot_group::del_member(const std::string& name)
	{
		return true;
	}
	
	bool bot_group::handle_message(int type, proto::avim_message_packet pkt)
	{
		std::cout << "get pkt" << std::endl;
		return true;
	}
	
}
