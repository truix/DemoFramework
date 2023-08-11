#include "../Includes/Frame-Include.h"

DemoFrame::cCryptInstance::cCryptInstance(CRYPT_TYPE Type, std::string Src, std::string Key, std::string IV)
	: oProtect(0)
{
	this->_iCryptType = Type;
	this->_Src = Src;
	this->_Key = Key;
	this->_IV = IV;
}

DemoFrame::cCryptInstance::~cCryptInstance()
{
}

DemoFrame::cCryptInstance::cCryptInstance(std::string Src)
	: oProtect(0)
{
	this->_iCryptType = CRYPT_TYPE_HASH_SHA;
	this->_Src = Src;
}

DemoFrame::cCryptInstance::cCryptInstance(CRYPT_TYPE Type, std::string Src)
{
		this->_iCryptType = Type;
		this->_Src = Src;
}

std::string DemoFrame::cCryptInstance::Execute()
{
	switch (this->_iCryptType)
	{
	case CRYPT_TYPE_ENCRYPT:
		return this->Encrypt(this->_Src, this->_Key, this->_IV);
	case CRYPT_TYPE_DECRYPT:
		return this->Decrypt(this->_Src, this->_Key, this->_IV);
	case CRYPT_TYPE_HASH_SHA:
		return this->SHA256Encode(this->_Src);
	case CRYPT_TYPE_HASH_MD5:
		return this->MD5Encode(this->_Src);
	case CRYPT_TYPE_COMPRESS:
		return this->Compress(this->_Src);
	case CRYPT_TYPE_DECOMPRESS:
		return this->DeCompress(this->_Src);
	case CRYPT_TYPE_BASE64ENCODE:
		return this->Base64Encode(this->_Src);
	case CRYPT_TYPE_BASE64DECODE:
		return this->Base64Decode(this->_Src);
	default:
		return VMProtectDecryptStringA("INVALID TYPE");
	}
}

std::string DemoFrame::cCryptInstance::SHA256Encode(std::string Src)
{
	VMProtectBeginMutation ("FRAME_SHA256");
	CryptoPP::SHA256 hash;
	byte digest[CryptoPP::SHA256::DIGESTSIZE];

	hash.CalculateDigest(digest, (unsigned char*)Src.c_str(), Src.length());

	std::string output;
	auto Sink = new CryptoPP::StringSink(output);

	CryptoPP::HexEncoder encoder(nullptr, false);
	encoder.Attach(Sink);
	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();

	return output;
	VMProtectEnd();
}

std::string DemoFrame::cCryptInstance::MD5Encode(std::string Src)
{
	VMProtectBeginMutation ("FRAME_MD5");
	CryptoPP::Weak::MD5 hash;
	byte digest[CryptoPP::Weak::MD5::DIGESTSIZE];

	hash.CalculateDigest(digest, (unsigned char*)Src.c_str(), Src.length());

	std::string output;
	auto Sink = new CryptoPP::StringSink(output);

	CryptoPP::HexEncoder encoder(nullptr, false);
	encoder.Attach(Sink);
	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();

	return output;
	VMProtectEnd();
}

std::string DemoFrame::cCryptInstance::Compress(std::string src)
{
	std::string Compressed;
	CryptoPP::Gzip zipper;
	zipper.Attach(new CryptoPP::StringSink(Compressed));
	zipper.Put(reinterpret_cast<const byte*>(src.c_str()), src.size());
	zipper.MessageEnd();
	return Compressed;
}

std::string DemoFrame::cCryptInstance::DeCompress(std::string src)
{
	std::string DeCompressed;
	CryptoPP::Gunzip unzipper;
	unzipper.Attach(new CryptoPP::StringSink(DeCompressed));
	unzipper.Put(reinterpret_cast<const byte*>(src.c_str()), src.size());
	unzipper.MessageEnd();
	return DeCompressed;
}

std::string DemoFrame::cCryptInstance::Base64Encode(std::string src)
{
	CryptoPP::Base64Encoder encoder;
	std::string Encoded;
	encoder.Attach(new CryptoPP::StringSink(Encoded));
	encoder.Put((unsigned char*)src.data(), src.size());
	encoder.MessageEnd();
	return Encoded;
}

std::string DemoFrame::cCryptInstance::Base64Decode(std::string src)
{
	CryptoPP::Base64Decoder decoder;
	std::string Decoded;
	decoder.Attach(new CryptoPP::StringSink(Decoded));
	decoder.Put((unsigned char*)src.data(), src.size());
	decoder.MessageEnd();
	return Decoded;
}

std::string DemoFrame::cCryptInstance::Encrypt(const std::string& Src, const std::string& Key, const std::string& IV)
{
	VMProtectBeginVirtualization("FRAME_Encrypt");
	std::string strOut;
	CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryption((unsigned char*)Key.c_str(), Key.length(), (unsigned char*)IV.c_str());
	auto Sink = new CryptoPP::StringSink(strOut);
	auto Encoder = new CryptoPP::Base64Encoder(Sink, false);
	auto Filter = new CryptoPP::StreamTransformationFilter(encryption, Encoder);
	CryptoPP::StringSource(Src, true, Filter);
	return strOut;
	VMProtectEnd();
}

std::string DemoFrame::cCryptInstance::Decrypt(const std::string& Src, const std::string& Key, const std::string& IV)
{
	VMProtectBeginVirtualization("FRAME_Decrypt");
	std::string strOut;
	CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryption((unsigned char*)Key.c_str(), Key.length(), (unsigned char*)IV.c_str());
	auto Sink = new CryptoPP::StringSink(strOut);
	auto Filter = new CryptoPP::StreamTransformationFilter(decryption, Sink);
	auto Decoder = new CryptoPP::Base64Decoder(Filter);
	CryptoPP::StringSource(Src, true, Decoder);

	return strOut;
	VMProtectEnd();
}