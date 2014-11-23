#pragma once

#include <unordered_map>
#include <boost/noncopyable.hpp>
#include <boost/thread.hpp>

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

static inline RSA * RSA_DumpPublicKey(RSA * pkey)
{
	RSA * pubkey = RSA_new();

	pubkey->e = BN_dup(pkey->e);
	pubkey->n = BN_dup(pkey->n);

	return pubkey;
}

inline std::string RSA_public_encrypt(RSA * rsa, const std::string & from)
{
	std::string result;
	const int keysize = RSA_size(rsa);
	std::vector<unsigned char> block(keysize);
	const int chunksize = keysize  - RSA_PKCS1_PADDING_SIZE;
	int inputlen = from.length();

	for(int i = 0 ; i < inputlen; i+= chunksize)
	{
		auto resultsize = RSA_public_encrypt(std::min(chunksize, inputlen - i), (uint8_t*) &from[i],  &block[0], (RSA*) rsa, RSA_PKCS1_PADDING);
		result.append((char*)block.data(), resultsize);
	}
	return result;
}

inline std::string RSA_private_decrypt(RSA * rsa, const std::string & from)
{
	std::string result;
	const int keysize = RSA_size(rsa);
	std::vector<unsigned char> block(keysize);

	for(int i = 0 ; i < from.length(); i+= keysize)
	{
		auto resultsize = RSA_private_decrypt(std::min<int>(keysize, from.length() - i), (uint8_t*) &from[i],  &block[0], rsa, RSA_PKCS1_PADDING);
		result.append((char*)block.data(), resultsize);
	}
	return result;
}

inline std::string RSA_private_encrypt(RSA * rsa, const std::string & from)
{
	std::string result;
	const int keysize = RSA_size(rsa);
	std::vector<unsigned char> block(keysize);
	const int chunksize = keysize  - RSA_PKCS1_PADDING_SIZE;
	int inputlen = from.length();

	for(int i = 0 ; i < from.length(); i+= chunksize)
	{
		int flen = std::min<int>(chunksize, inputlen - i);

		std::fill(block.begin(),block.end(), 0);

		auto resultsize = RSA_private_encrypt(
			flen,
			(uint8_t*) &from[i],
			&block[0],
			rsa,
			RSA_PKCS1_PADDING
		);
		result.append((char*)block.data(), resultsize);
	}
	return result;
}

inline std::string RSA_public_decrypt(RSA * rsa, const std::string & from)
{
	std::string result;
	const int keysize = RSA_size(rsa);
	std::vector<unsigned char> block(keysize);

	int inputlen = from.length();

	for(int i = 0 ; i < from.length(); i+= keysize)
	{
		int flen = std::min(keysize, inputlen - i);

		auto resultsize = RSA_public_decrypt(
			flen,
			(uint8_t*) &from[i],
			&block[0],
			rsa,
			RSA_PKCS1_PADDING
		);
		result.append((char*)block.data(), resultsize);
	}
	return result;
}


namespace bot_avim {
	
	class bot_ca
		: public boost::noncopyable
	{
	public:
		explicit bot_ca(boost::shared_ptr<RSA> rsa, boost::shared_ptr<X509> x509_cert);
		~bot_ca();

	public:
		bool dh_generate_clientkey();
		bool dh_generate_client_shared_key();
		
		std::string private_encrypt(RSA * rsa, const std::string & from);
		std::string public_encrypt(RSA * rsa, const std::string & from);
		std::string private_decrypt(RSA * rsa, const std::string & from);
		std::string public_decrypt(RSA * rsa, const std::string & from);

	private:
		boost::shared_ptr<RSA> m_rsa;
		boost::shared_ptr<X509> m_x509_cert;
		
		DH *dh_client;
		std::string dh_random_g, dh_random_p;
		std::string dh_client_pubkey;
		std::string dh_server_pubkey;
		std::vector<uint8_t> dh_client_shared_key;
		std::vector<uint8_t> dh_server_shared_key;
		
		boost::shared_ptr<RSA> rsa_key;
		boost::shared_ptr<X509> x509_cert;
	};
	
}