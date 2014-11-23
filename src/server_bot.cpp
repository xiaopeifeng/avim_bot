// 
// Simple app with avim_bot
//
// Group bot Impl
//

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

#include "bot_api.hpp"
#include "logging.hpp"

fs::path setup_ini;
int bot_port;
static fs::path bot_key;
static fs::path bot_cert;

std::string content_key, content_cert, bot_phase;

void program_options_load(int argc, char **argv)
{
	po::options_description desc("Allowed options");
	po::variables_map vm;
	
	desc.add_options()
	("help,h", "produce help message")
	("version,v", "print version string")
	("key", po::value<fs::path>(&bot_key)->default_value("bot.key"), "path to private key")
	("cert", po::value<fs::path>(&bot_cert)->default_value("bot.crt"), "path to cert")
	("ini", po::value<fs::path>(&setup_ini)->default_value("group.ini"), "path to group bot setup ini file")
	("port", po::value<int>(&bot_port)->default_value(33221), "port bind to bot server")
	;
	
	po::store(po::parse_command_line(argc, argv, desc), vm);
	po::notify(vm);
	
	if(argc == 1 || vm.count("help"))
	{
		LOG_DBG << desc;
		return;
	}
	
	if(vm.count("version"))
	{
		LOG_DBG << "Version:0.1";
		return;
	}
	
	return;
}
int main(int argc, char **argv)
{
	bot_context_t *bot_ctx = new bot_context_t;
	LOG_DBG << "Group bot starting ";
	program_options_load(argc, argv);
	
	bot_ctx->key_path = const_cast<char *>(bot_key.c_str());
	bot_ctx->cert_path = const_cast<char *>(bot_cert.c_str());

	bot_ctx->role = 0; // 0 client 1 group
	bot_init(bot_ctx);
	
#if 0
	boost::shared_ptr<BIO> shared_keyfile(BIO_new_mem_buf(&keyfilecontent[0], keyfilecontent.length()), BIO_free);
	boost::shared_ptr<BIO> shared_certfile(BIO_new_mem_buf(&certfilecontent[0], certfilecontent.length()), BIO_free);

	boost::shared_ptr<RSA> rsa_key_tmp(
		PEM_read_bio_RSAPrivateKey(shared_keyfile.get(), 0, (pem_password_cb*)pass_cb,(void*) key.c_str()),
		RSA_free
	);
	
	
	bot_init();
	while(1)
	{
		sleep(1);
	}
#endif
	return 0;
}
