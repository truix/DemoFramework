#pragma once

namespace DemoFrame {
	class NetworkWorker {
	public:
		NetworkWorker() = default;

		NetworkWorker(std::string key, std::string iv, std::string User) : Keypart1(key), Keypart2(iv), UserAgent(User)
		{
		}

		~NetworkWorker() = default;

		nlohmann::json SendAPIRequest(std::string action, nlohmann::json requestdata);

		nlohmann::json SendSecureRequest(std::string url, std::string location);

		std::string SendTokenRequest(std::string url, std::string location, std::string token);

		nlohmann::json SendDriverRequest(std::string url, std::string location, std::string key, std::string iv);

		std::string SendRequest(std::string url, std::string location, std::string data);

		static size_t DataCallback(char *contents, size_t size, size_t nmemb, void *userp);

		static size_t ReadCallback(void *dest, size_t size, size_t nmemb, void *userp);
	private:
		enum Flags {
			API_REQUEST = 1 << 6,
			SECURE_REQUEST = 1 << 8,
			TOKEN_REQUEST = 1 << 10,
			DRIVER_REQUEST = 1 << 12,
			NO_PROTO = 1 << 0,

		};
		struct WriteThis {
			const char *readptr;
			size_t sizeleft;
		};
		enum RequestType {
			POST = 1 << 7,
			GET = 2 << 4,
		};
	public:
		std::string Encrypt(std::string compressed);
		std::string Decrypt(std::string recvd, std::string token = "", std::string key = "", std::string iv = "");
	private:
		std::string Compress(std::string Data);

		std::string Send(std::string url, std::string location, std::string post, std::string token = "", std::string key = "", std::string iv = "");
		
		std::string Decompress(std::string decrypted);

		nlohmann::json CheckAction(std::string decompressed);

		std::string UserAgent, Keypart1, Keypart2;
		Flags Type = NO_PROTO;
		RequestType Method = GET;
	};
}