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

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#include "bot_group.hpp"

static boost::asio::io_service io_service;

/*
 * 
 * 0 - group service
 * 1 - to be continued
 * 
 */
static int service_type = 0; 

static std::string keycontent;
static std::string crtcontent;

int pass_cb(char *buf, int size, int rwflag, char *u)
{
	int len;
	std::string tmp;
	/* We'd probably do something else if 'rwflag' is 1 */
	std::cout << "Enter pass phrase for " << u << " :";
	std::flush(std::cout);

	std::cin >> tmp;

	/* get pass phrase, length 'len' into 'tmp' */
	len = tmp.length();

	if (len <= 0) return 0;
	/* if too long, truncate */
	if (len > size) len = size;
	memcpy(buf, tmp.data(), len);
	return len;
}

int main(int argc, char* argv[])
{
	OpenSSL_add_all_algorithms();
	fs::path key, cert;
	std::string to;

	po::variables_map vm;
	po::options_description desc("qqbot options");
	desc.add_options()
	("key", po::value<fs::path>(&key)->default_value("test.key"), "path to private key")
	("cert", po::value<fs::path>(&cert)->default_value("test.crt"), "path to cert")
	("help,h", "display this help")
	("service", po::value<int>(&service_type)->default_value(0), "service type, 0 - group service")
	("to", po::value<std::string>(&to), "send test message to, default to send to your self");
	

	po::store(po::parse_command_line(argc, argv, desc), vm);
	po::notify(vm);

	if (vm.count("help"))
	{
		std::cerr << desc << std::endl;
		return 1;
	}

	if (!fs::exists(key))
	{
		std::cerr <<  desc <<  std::endl;
		std::cerr << "can not open " << key << std::endl;
		exit(1);
	}
	if (!fs::exists(cert))
	{
		std::cerr <<  desc <<  std::endl;
		std::cerr << "can not open " << cert << std::endl;
		exit(1);
	}

	std::string keyfilecontent, keyfilecontent_decrypted, certfilecontent;

	{
		std::ifstream keyfile(key.string().c_str(), std::ios_base::binary | std::ios_base::in);
		std::ifstream certfile(cert.string().c_str(), std::ios_base::binary | std::ios_base::in);
		keyfilecontent.resize(fs::file_size(key));
		certfilecontent.resize(fs::file_size(cert));
		keyfile.read(&keyfilecontent[0], fs::file_size(key));
		certfile.read(&certfilecontent[0], fs::file_size(cert));
	}

	// 这里通过读取然后写回的方式预先将私钥的密码去除

	boost::shared_ptr<BIO> keyfile(BIO_new_mem_buf(&keyfilecontent[0], keyfilecontent.length()), BIO_free);
	boost::shared_ptr<RSA> rsa_key(
		PEM_read_bio_RSAPrivateKey(keyfile.get(), 0, (pem_password_cb*)pass_cb,(void*) key.c_str()),
		RSA_free
	);

	keyfile.reset(BIO_new(BIO_s_mem()), BIO_free);
	char *outbuf = 0;
	PEM_write_bio_RSAPrivateKey(keyfile.get(),rsa_key.get(), 0, 0, 0, 0, 0);
	rsa_key.reset();
	auto l = BIO_get_mem_data(keyfile.get(), &outbuf);
	keyfilecontent.assign(outbuf, l);
	keyfile.reset();
	
	keycontent = keyfilecontent;
	crtcontent = certfilecontent;

	std::cout << "get key cert conternt \n";
	
	boost::shared_ptr<bot_avim::bot_group> group_service;
	
	if(service_type == 0)
	{
		std::cout << "Strat group service." << std::endl;
		group_service.reset(new bot_avim::bot_group(io_service, keycontent, crtcontent));
		//bot_group group_service(io_service, keycontent, crtcontent);
	}
	else
	{
		std::cout << "service unkown." << std::endl;
		exit(1);
	}	
	
	io_service.run();
}


