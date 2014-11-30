#include "logging.hpp"
#include "bot_ca.hpp"

namespace bot_avim {

	bot_ca::bot_ca(boost::shared_ptr<RSA> rsa, boost::shared_ptr<X509> x509_cert)
		: m_rsa(rsa)
		, m_x509(x509_cert)
	{
		LOG_DBG << "bot ca constructor";
	}

	bot_ca::~bot_ca()
	{}

	bool bot_ca::dh_generate_clientkey()
	{
		unsigned char client_content[512] = {0};
		dh_client = DH_new();
		DH_generate_parameters_ex(dh_client,64,DH_GENERATOR_5,NULL);
		DH_generate_key(dh_client);

		dh_random_g.assign(reinterpret_cast<const char*>(client_content), BN_bn2bin(dh_client->g, client_content));
		dh_random_p.assign(reinterpret_cast<const char*>(client_content), BN_bn2bin(dh_client->p, client_content));
		dh_client_pubkey.assign(reinterpret_cast<const char*>(client_content), BN_bn2bin(dh_client->pub_key, client_content));

		return true;
	}

	bool bot_ca::dh_generate_client_shared_key()
	{
		dh_client_shared_key.resize(DH_size(dh_client));
		BIGNUM* client_server_pubkey = BN_bin2bn((const unsigned char *)dh_server_pubkey.data(), static_cast<long>(dh_server_pubkey.length()), NULL);
		DH_compute_key(&dh_client_shared_key[0], client_server_pubkey, dh_client);
		BN_free(client_server_pubkey);
		DH_free(dh_client);

		std::string client_key;
		char buf[16] = { 0 };
		for (int i=0; i< dh_client_shared_key.size(); ++i)
		{
			sprintf(buf, "%x%x", (dh_client_shared_key[i] >> 4) & 0xf, dh_client_shared_key[i] & 0xf);
			client_key += buf;
		}
		
		LOG_DBG << "Generate client shared key:" << client_key;
		return 0;
	}
	
	std::string &bot_ca::get_random_g()
	{
		return dh_random_g;
	}
	
	std::string &bot_ca::get_random_p()
	{
		return dh_random_p;
	}
	
	std::string &bot_ca::get_pubkey()
	{
		return dh_client_pubkey;
	}
	
	bool bot_ca::set_server_pubkey(std::string &pubkey)
	{
		dh_server_pubkey = pubkey;
		return true;
	}
	
	boost::shared_ptr<X509> bot_ca::get_shared_x509()
	{
		return m_x509;
	}
	
	std::string bot_ca::private_encrypt(const std::string & from)
	{	
		return RSA_private_encrypt(m_rsa.get(), from);
	}

	std::string bot_ca::public_encrypt(const std::string & from)
	{
		EVP_PKEY *key_tmp = X509_get_pubkey(m_x509.get());
		rsa_st *user_rsa_pubkey = EVP_PKEY_get1_RSA(key_tmp);
		EVP_PKEY_free(key_tmp);
		return RSA_public_encrypt(user_rsa_pubkey, from);
	}

	std::string bot_ca::private_decrypt(const std::string & from)
	{
		return RSA_private_decrypt(m_rsa.get(), from);
	}

	std::string bot_ca::public_decrypt(const std::string & from)
	{
		EVP_PKEY *key_tmp = X509_get_pubkey(m_x509.get());
		rsa_st *user_rsa_pubkey = EVP_PKEY_get1_RSA(key_tmp);
		EVP_PKEY_free(key_tmp);
		return RSA_public_decrypt(user_rsa_pubkey, from);
	}
	
	
}
