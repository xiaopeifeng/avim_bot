#include "logging.hpp"
#include "bot_ca.hpp"

namespace bot_avim {

	bot_ca::bot_ca(boost::shared_ptr<RSA> rsa, boost::shared_ptr<X509> x509_cert)
		: m_rsa(rsa)
		, m_x509_cert(x509_cert)
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
	
	
	std::string bot_ca::private_encrypt(RSA * rsa, const std::string & from)
	{
		return RSA_private_encrypt(rsa, from);
	}

	std::string bot_ca::public_encrypt(RSA * rsa, const std::string & from)
	{
		return RSA_public_encrypt(rsa, from);
	}

	std::string bot_ca::private_decrypt(RSA * rsa, const std::string & from)
	{
		return RSA_private_decrypt(rsa, from);
	}

	std::string bot_ca::public_decrypt(RSA * rsa, const std::string & from)
	{
		return RSA_public_decrypt(rsa, from);
	}
	
	
}
