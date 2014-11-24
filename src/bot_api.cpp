#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#include <iostream>
#include <fstream>

#include <boost/format.hpp>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/make_shared.hpp>
#include <boost/thread.hpp>
#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;

#include "bot_api.hpp"
#include "bot_server.hpp"
#include "logging.hpp"

using namespace bot_avim;

static int pass_cb(char *buf, int size, int rwflag, char *u)
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

int bot_init(bot_context_t *ctx)
{
	// CA LOAD
	OpenSSL_add_all_algorithms();
	fs::path bot_key(ctx->key_path);
	fs::path bot_cert(ctx->cert_path);
	
	std::ifstream file_key(bot_key.c_str(), std::ios_base::binary | std::ios_base::in);
	std::ifstream file_cert(bot_cert.c_str(), std::ios_base::binary | std::ios_base::in);
	
	std::string content_key, content_cert;
	
	content_key.resize(fs::file_size(bot_key));
	content_cert.resize(fs::file_size(bot_cert));
	
	file_key.read(&content_key[0], fs::file_size(bot_key));
	file_cert.read(&content_cert[0], fs::file_size(bot_cert));
	
	boost::shared_ptr<BIO> shared_keyfile(BIO_new_mem_buf(&content_key[0], content_key.length()), BIO_free);
	boost::shared_ptr<BIO> shared_certfile(BIO_new_mem_buf(&content_cert[0], content_cert.length()), BIO_free);

	boost::shared_ptr<RSA> rsa_key(
		PEM_read_bio_RSAPrivateKey(shared_keyfile.get(), 0, (pem_password_cb*)pass_cb,(void*) bot_key.c_str()),
		RSA_free
	);
	shared_keyfile.reset(BIO_new(BIO_s_mem()), BIO_free);


	boost::shared_ptr<X509> x509_cert;
	x509_cert.reset(PEM_read_bio_X509(shared_certfile.get(), 0, 0, 0), X509_free);
	//LOG_DBG << content_key;
	//LOG_DBG << content_cert;
	
	//SERVER START
	bot_server server(rsa_key, x509_cert);
	server.set_role(static_cast<bot_role>(ctx->role));
	server.set_conn(std::string(ctx->bot_addr), ctx->bot_port, std::string(ctx->server_addr), ctx->server_port);
	server.start();
    return 0;
}

int bot_send_message()
{
    return 0;
}

int bot_recv_message()
{
    return 0;
}

int bot_register_cb(bot_cb cb)
{
}

int bot_stop()
{
    return 0;
}


