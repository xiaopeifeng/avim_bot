#include "logging.hpp"
#include "bot_client.hpp"
#include "group.pb.h"

namespace bot_avim {

	bot_client::bot_client(boost::asio::io_service& io_service, std::shared_ptr<RSA> key, std::shared_ptr<X509> crt)
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
				std::string target("peter@avplayer.org");
				m_avproto.get()->write_packet(target, content);
				std::cout << "send test pkt ok" << std::endl;

				// get group list
#if 0
				proto::group::list_request request;
				request.set_id(0);
				std::string addr_group("group@avplayer.org");
				std::string from("peter@avplayer.org");
				std::string group_content = encode_control_message(from, request);
				m_avproto.get()->write_packet(addr_group, group_content);
#endif
				return true;
			}
		}
	}

	bool bot_client::handle_message(const std::string& sender, const std::string& content)
	{
		std::cout << "get im message" << std::endl;
		if (is_encrypted_message(content))
		{
			// TODO
			std::string key = "解码 group 消息的对称密码";
			// TODO decode_im_message(key, content);
		}

		im_message msgpkt = decode_im_message(content);

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
		const std::string type_name = msg_ptr.get()->GetTypeName();
		std::cout << type_name << std::endl;
		if(type_name == "proto.group.list_response")
		{
			proto::group::list_response *response_ptr = dynamic_cast<proto::group::list_response *>(msg_ptr.get());
			std::cout << "receive group list response" << std::endl;
			if(response_ptr->result() != proto::group::list_response_result_code::list_response_result_code_OK)
			{
				std::cout << "group request failed " << std::endl;
				return false;
			}

			int size = response_ptr->list_size();
			std::cout << "list count " << size << std::endl;
			for(int i=0; i < size; i++)
			{
				std::string addr = response_ptr->list(i);
				std::cout << addr << std::endl;
			}

			return true;

		}

		return false;
	}

}
