#include "logging.hpp"
#include "bot_group.hpp"

namespace bot_avim {

	bot_group::bot_group(boost::asio::io_service& io_service, std::string key, std::string crt)
	: bot_service(io_service, key, crt)
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
		
		m_avproto.reset(new avproto_wrapper(io_service, key, crt));
		
		m_avproto.get()->register_service(this);
		m_avproto.get()->start();
		
		LOG_DBG << "bot group constructor";
	}

	bot_group::~bot_group()
	{}

	bool bot_group::notify(int cmd, int ext1, int ext2)
	{
		if(cmd == CMD_STATE_CHANGED)
		{
			m_status = static_cast<group_status>(ext1);
			if(m_status == GROUP_STATUS_ONLINE)
			{
				// send test pkt
				message::message_packet pkt;
				pkt.mutable_avim()->Add()->mutable_item_text()->set_text("test");
				m_avproto.get()->write_msg("test-client@avplayer.org", pkt);
				return true;
			}
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
	
	bool bot_group::handle_message(int type, std::string &sender, im_message msgpkt)
	{
		std::cout << "get pkt" << std::endl;
		
		if(msgpkt.is_group_message == 0)
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
		
		if(sender == "group@avplayer.org")
		{
			std::cout << "From group, maybe test pkt" << std::endl;
			return true;
		}
		
		// Send Group List to member		
		for(int i = 0; i < m_group_member_list.size(); i++)
		{
			if(sender == m_group_member_list.at(i))
			{
				continue;
			}
			std::cout << "Trans avpkt to: " << m_group_member_list.at(i) <<" From: " << sender << std::endl;
			m_avproto.get()->write_msg(m_group_member_list.at(i), msgpkt.impkt);
		}	
		
		return true;
	}
	
}
