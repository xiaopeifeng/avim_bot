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
				std::string content = encode_im_message(pkt);
				m_avproto.get()->write_packet("peter@avplayer.org", content);
				
				// get group list
#if 0	
				message::message_packet request_pkt;
				message::group_request *request = request_pkt.mutable_avim()->Add()->mutable_item_group_request();
				request->set_group_id(0);
				request->set_request_id(message::group_request::request_type::group_request_request_type_GROUP_REQUEST_LIST);
				request->set_group_name("avim main group");
				std::string request_content = encode_control_message(request_pkt);
				m_avproto.get()->write_packet("group@avplayer.org", request_content);
#endif
				return true;
			}
		}
	}
	
	bool bot_client::handle_message(int type, std::string &sender, im_message msgpkt)
	{
		std::cout << "get im message" << std::endl;

		for (message::avim_message im_message_item : msgpkt.impkt.avim())
		{
			if (im_message_item.has_item_text())
			{
				std::cerr << im_message_item.item_text().text() << std::endl;
			}
		}
		
		return true;
	}
	
	bool bot_client::handle_message(int type, std::string &sender, std::shared_ptr<google::protobuf::Message> msg_ptr)
	{
		std::cout << "get pkt" << std::endl;
		const std::string msg_type = msg_ptr.get()->GetTypeName();

		if(msg_type == "message.message_packet")
		{
			message::message_packet *msgpkt = dynamic_cast<message::message_packet*>(msg_ptr.get());
			for (message::avim_message im_message_item : msgpkt->avim())
			{
				if (im_message_item.has_item_text())
				{
					std::cerr << im_message_item.item_text().text() << std::endl;
				}
	#if 0
				if(im_message_item.has_item_group_response())
				{
					std::cout << "receive group list response" << std::endl;
					if(im_message_item.item_group_response().result() != message::group_response::result_code::group_response_result_code_OK)
					{
						std::cout << "group request failed " << std::endl;
						return false;
					}
					
					if(im_message_item.item_group_response().response_id() == 0)
					{
						std::cout << "group list query result " << std::endl;
						int size = im_message_item.item_group_response().group_list_item().member_list_item_size();
						std::cout << "list count " << size << std::endl;
						for(int i=0; i < size; i++)
						{
							message::group_list::member_list addr = im_message_item.item_group_response().group_list_item().member_list_item(i);
							std::cout << addr.addr() << std::endl;
						}
					}
					
				}
	#endif
				
			}
		}
		
		return true;
	}
	
}
