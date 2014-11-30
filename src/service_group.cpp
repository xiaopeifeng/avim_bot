#include <string>
#include <iostream>
#include <fstream>
#include <boost/format.hpp>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/make_shared.hpp>
#include <boost/thread.hpp>
#include <boost/program_options.hpp>
namespace po = boost::program_options;
#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;

#include "avjackif.hpp"
#include "avproto.hpp"
#include "message.hpp"
#include "avim.hpp"

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

// 一个非常非常简单的 IM 实现，测试用途

boost::scoped_ptr<avim_client> avim;

std::vector<std::string> m_group_list;

void send_msb_cb(boost::system::error_code ec)
{
	if(ec)
		std::cout << "send failed, err msg:" << ec.message()  <<std::endl;
}

static void msg_reader(boost::asio::yield_context yield_context)
{
	boost::system::error_code ec;
	proto::av_address sender;
	proto::avim_message_packet msgpkt;

	for (;;)
	{
		avim->async_recv_im([](proto::av_address){return false;}, sender, msgpkt, yield_context);
	
		std::cerr << "接收到的数据： " << av_address_to_string(sender) << "说: ";

		for (proto::avim_message im_message_item : msgpkt.avim())
		{
			if (im_message_item.has_item_text())
			{
				std::cerr << im_message_item.item_text().text() << std::endl;
			}
		}

		std::cerr << std::endl;
#if 0
		if(av_address_to_string(sender) == "group@avplayer.org")
		{
			std::cout << "From group, maybe test pkt" << std::endl;
			continue;
		}
		
		// CMD-HANDLE
		// Send Group List to member		
		for(int i = 0; i < m_group_list.size(); i++)
		{
			//if(av_address_to_string(sender) == m_group_list.at(i))
			//{
			//	continue;
			//}
			std::cout << "Trans avpkt to: " << m_group_list.at(i) <<" From: " << av_address_to_string(sender) << std::endl;
			//avim->async_send_im(av_address_from_string(m_group_list.at(i)), msgpkt, yield_context);
			avim->async_send_im(av_address_from_string(m_group_list.at(i)), msgpkt, send_msb_cb);
			
		}	
#endif

#if 0
		proto::avim_message_packet response;
		response.mutable_avim()->Add()->mutable_item_text()->set_text("Jack@avplayer.org");
		response.mutable_avim()->Add()->mutable_item_text()->set_text("dpainter@avplayer.org");
		response.mutable_avim()->Add()->mutable_item_text()->set_text("hyq@avplayer.org");
		response.mutable_avim()->Add()->mutable_item_text()->set_text("luofei@avplayer.org");
		response.mutable_avim()->Add()->mutable_item_text()->set_text("michael.fan@avplayer.org");
		response.mutable_avim()->Add()->mutable_item_text()->set_text("microcai@avplayer.org");
		response.mutable_avim()->Add()->mutable_item_text()->set_text("mrshelly@avplayer.org");
		response.mutable_avim()->Add()->mutable_item_text()->set_text("xosdy@avplayer.org");
		response.mutable_avim()->Add()->mutable_item_text()->set_text("zxf@avplayer.org");
		response.mutable_avim()->Add()->mutable_item_text()->set_text("peter@avplayer.org");
		response.mutable_avim()->Add()->mutable_item_text()->set_text("test-client@avplayer.org");
		std::cout << "send list to: " << av_address_to_string(sender) << std::endl;
		avim->async_send_im(av_address_from_string(av_address_to_string(sender)), response, yield_context);	
#endif
	}
}

static void msg_login_and_send(std::string to, boost::asio::yield_context yield_context)
{
	avim->async_wait_online(yield_context);

	std::string msg = std::string("test, me are sending a test message to ") + to + " stupid!";

	proto::avim_message_packet msgpkt;
	msgpkt.mutable_avim()->Add()->mutable_item_text()->set_text(msg);

	if (to.empty())
	{
		//avim->async_send_im(avim->self_address(), msgpkt, yield_context);
		avim->async_send_im(avim->self_address(), msgpkt, send_msb_cb);
	}
	else
	{
		// 进入 IM 过程，发送一个 test  到 test2@avplayer.org
		//avim->async_send_im(av_address_from_string(to), msgpkt, yield_context);
		avim->async_send_im(av_address_from_string(to), msgpkt, send_msb_cb);
	}
	
	
}

bool service_group_start(boost::asio::io_service &ios, std::string key, std::string crt)
{
	m_group_list.push_back("Jack@avplayer.org");
	m_group_list.push_back("dpainter@avplayer.org");
	m_group_list.push_back("hyq@avplayer.org");
	m_group_list.push_back("luofei@avplayer.org");
	m_group_list.push_back("michael.fan@avplayer.org");
	m_group_list.push_back("microcai@avplayer.org");
	m_group_list.push_back("mrshelly@avplayer.org");
	m_group_list.push_back("xosdy@avplayer.org");
	m_group_list.push_back("zxf@avplayer.org");
	m_group_list.push_back("peter@avplayer.org");
	m_group_list.push_back("test-client@avplayer.org");
	
	std::string to("test-client@avplayer.org");
	// 读入 key 和 cert 的内容
	avim.reset(new avim_client(ios, key, crt));
	boost::asio::spawn(ios, boost::bind(&msg_login_and_send, to, _1));
	// 开协程异步接收消息
	boost::asio::spawn(ios, msg_reader);
}