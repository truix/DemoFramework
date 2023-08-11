#pragma once

namespace DemoFrame
{
	enum CRYPT_TYPE
	{
		CRYPT_TYPE_ENCRYPT = 2 << 4,
		CRYPT_TYPE_DECRYPT,
		CRYPT_TYPE_HASH_SHA,
		CRYPT_TYPE_HASH_MD5,
		CRYPT_TYPE_COMPRESS,
		CRYPT_TYPE_DECOMPRESS,
		CRYPT_TYPE_BASE64ENCODE,
		CRYPT_TYPE_BASE64DECODE,
	};

	class cCryptInstance
	{
	public:
		cCryptInstance(CRYPT_TYPE, std::string, std::string, std::string);
		~cCryptInstance();
		cCryptInstance(std::string);
		cCryptInstance(CRYPT_TYPE, std::string);
		std::string Execute();

	private:
		std::string Encrypt(const std::string&, const std::string&, const std::string&);
		std::string Decrypt(const std::string&, const std::string&, const std::string&);
		std::string SHA256Encode(std::string src);
		std::string MD5Encode(std::string src);
		std::string Compress(std::string src);
		std::string DeCompress(std::string src);
		std::string Base64Encode(std::string src);
		std::string Base64Decode(std::string src);

		CRYPT_TYPE _iCryptType;
		std::string _Src, _Key, _IV;
		DWORD oProtect;
	};
}