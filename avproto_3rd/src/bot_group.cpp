#include "logging.hpp"
#include "bot_server.hpp"
#include "bot_group.hpp"

namespace bot_avim {

	bot_group::bot_group(bot_server& serv)
	: m_server(serv)
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
		
		LOG_DBG << "bot group constructor";
	}

	bot_group::~bot_group()
	{}

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
	
	bool bot_group::handle_message(google::protobuf::Message* msg)
	{
		proto::avpacket* pkt = dynamic_cast<proto::avpacket*>(msg);
		
		// check agmp
		if(pkt->mutable_upperlayerpotocol()->compare("agmp") == 0)
		{
			LOG_DBG << "dest not reached, skipped";
			return false;
		}
		
		for(int i = 0; i < m_group_member_list.size(); i++)
		{
			if(pkt->src().username() == m_group_member_list.at(i))
				continue;
			// trans
			pkt->mutable_dest()->CopyFrom(av_address_from_string(m_group_member_list.at(i)));
			m_server.write_packet(encode(*pkt));
			LOG_DBG << "Trans avpkt to: " << m_group_member_list.at(i) <<" From: " << pkt->src().username();
		}
		//delete pkt;
		return true;
	}
	
	void bot_group::dump_status()
	{
#if 0
		for(int i = 0; i < m_group_member_list.size(); i++)
		{
			LOG_DBG << m_group_member_list.at(i);
		}
#endif		
		member_ptr::iterator it;
		for (it =m_group_member_list.begin(); it !=m_group_member_list.end(); ++it)
			LOG_DBG << *it;
	}
	
}
