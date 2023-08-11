#include "../Includes/Frame-Include.h"


nlohmann::json DemoFrame::NetworkWorker::SendAPIRequest(std::string action, nlohmann::json requestdata) {

	Method = POST;
	Type = API_REQUEST;
	auto datapackage = requestdata;
	std::string username = "", password = "";

	if (!requestdata[VMProtectDecryptStringA("username")].empty())
		username = requestdata[VMProtectDecryptStringA("username")].get<std::string>();

	if (!requestdata[VMProtectDecryptStringA("password")].empty())
		password = requestdata[VMProtectDecryptStringA("password")].get<std::string>();

	

	datapackage.emplace(std::string(VMProtectDecryptStringA("action")).c_str(), action);

	datapackage = nlohmann::json::merge(datapackage, DemoFrame::Utils::GetUIDJSON(false, username, password));

	return CheckAction(Send(VMProtectDecryptStringA("https://api.Demo"), VMProtectDecryptStringA("/auth.php"), datapackage.dump()));
	
}


nlohmann::json DemoFrame::NetworkWorker::SendSecureRequest(std::string url, std::string location) {

	Method = POST;
	Type = SECURE_REQUEST;

	return CheckAction(Send(url, location, ""));
}

std::string DemoFrame::NetworkWorker::SendTokenRequest(std::string url, std::string location, std::string token) {

	Method = GET;
	Type = TOKEN_REQUEST;

	return Send(url, location, "", token);
}

nlohmann::json DemoFrame::NetworkWorker::SendDriverRequest(std::string url, std::string location, std::string key, std::string iv) {

	Method = GET;
	Type = DRIVER_REQUEST;

	return nlohmann::json::parse(Send(url, location, "", "", key, iv));
}

std::string DemoFrame::NetworkWorker::SendRequest(std::string url, std::string location, std::string post) {
	if (!post.empty())
		Method = POST;

	Type = NO_PROTO;

	return Send(url, location, post);
}

size_t DemoFrame::NetworkWorker::DataCallback(char* contents, size_t size, size_t nmemb, void* userp) {
	((std::string*)userp)->append((char*)contents, size * nmemb);
	return size * nmemb;
}

size_t DemoFrame::NetworkWorker::ReadCallback(void* dest, size_t size, size_t nmemb, void* userp) {
	struct WriteThis *wt = static_cast<struct WriteThis *>(userp);
	const size_t buffer_size = size * nmemb;

	if (wt->sizeleft) {
		size_t copy_this_much = wt->sizeleft;
		if (copy_this_much > buffer_size)
			copy_this_much = buffer_size;
		memcpy(dest, wt->readptr, copy_this_much);

		wt->readptr += copy_this_much;
		wt->sizeleft -= copy_this_much;
		return copy_this_much;
	}

	return 0;
}

std::string DemoFrame::NetworkWorker::Encrypt(std::string compressed) {
	auto string = Keypart1 + Keypart2;
	auto key = DemoFrame::Utils::CreateKey(string);
	return DemoFrame::cCryptInstance(DemoFrame::CRYPT_TYPE_ENCRYPT, compressed, key.substr(0, 32), key.substr(32, 48)).Execute();
}

std::string DemoFrame::NetworkWorker::Compress(std::string Data) {
	return DemoFrame::cCryptInstance(DemoFrame::CRYPT_TYPE_COMPRESS, Data).Execute();
}

std::string DemoFrame::NetworkWorker::Send(std::string url, std::string location, std::string data, std::string token, std::string key, std::string iv) {
	CURLcode res;

	curl_global_init(CURL_GLOBAL_DEFAULT);

	CURL *curl = curl_easy_init();

	if (!curl) {
		//MessageBoxA(0, VMProtectDecryptStringA("Error: 900 a1"), VMProtectDecryptStringA("Error"), MB_OK);
		TerminateProcess(0, 0xDEADBEEF);
		return "";
	}

	std::string prepared = "";
	std::string spoofed = "";
	std::string prepareddata = Encrypt(Compress(data));
	if ((Type == API_REQUEST) || (Type == SECURE_REQUEST)) {
		if (Method == GET) {
			prepared += VMProtectDecryptStringA("?session=");
			prepared += prepareddata;
		}

		if (Method == POST) {
			prepared += VMProtectDecryptStringA("&session=");//remove this for post information to spoof it And append spoofed data
			prepared += prepareddata;

			spoofed += VMProtectDecryptStringA("?session=");
			spoofed += cCryptInstance(CRYPT_TYPE_ENCRYPT, cCryptInstance( Utils::getTimeStamp()).Execute() + Utils::GenerateRandomName(200), Utils::GenerateRandomName(32), Utils::GenerateRandomName(16)).Execute();
		}	
	}
	else {
		prepared = data;
	}

	std::string recv = "";

	if ((Type == API_REQUEST) || (Type == SECURE_REQUEST) || (Type == TOKEN_REQUEST) || (Type == DRIVER_REQUEST)) {

		struct curl_slist *chunk = NULL;

		chunk = curl_slist_append(chunk, std::string(VMProtectDecryptStringA("Client:") + DemoFrame::cCryptInstance(DemoFrame::CRYPT_TYPE_HASH_SHA,
								  Keypart1 + Keypart2).Execute()).data());

		chunk = curl_slist_append(chunk, VMProtectDecryptStringA("Content-Type: application/json"));

		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
	}


	if (Method == GET) {
		curl_easy_setopt(curl, CURLOPT_URL, (url + location + prepared).data());
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_POST, 0L);
		//curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
		//curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, DataCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &recv);
		curl_easy_setopt(curl, CURLOPT_USERAGENT, UserAgent.data());
		curl_easy_setopt(curl, CURLOPT_PORT, 443);

		curl_easy_perform(curl);

		curl_easy_cleanup(curl);
		
	}

	if (Method == POST) {
		WriteThis wt;
		wt.readptr = prepared.c_str();
		wt.sizeleft = prepared.size();

		curl_easy_setopt(curl, CURLOPT_URL, (url + location).data()); 
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
		
		curl_easy_setopt(curl, CURLOPT_POST, 1L);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, DataCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &recv);
		curl_easy_setopt(curl, CURLOPT_READFUNCTION, ReadCallback);
		curl_easy_setopt(curl, CURLOPT_READDATA, &wt);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(wt.sizeleft));
		curl_easy_setopt(curl, CURLOPT_USERAGENT, UserAgent.data());
		curl_easy_setopt(curl, CURLOPT_PORT, 443);

		curl_easy_perform(curl);

		curl_easy_cleanup(curl);
		
	}

	curl_global_cleanup();

	if ((Type == API_REQUEST) || (Type == SECURE_REQUEST)) {
		if (recv.size() > 0) {
			auto object = nlohmann::json::parse(recv);
			recv = Decompress(Decrypt(object["1"].get<std::string>()));
		}
	}

	if ((Type == TOKEN_REQUEST)) {
		if (recv.size() > 0) {
			auto object = nlohmann::json::parse(recv);
			recv = Decompress(Decrypt(object["1"].get<std::string>(), token));
		}
	}

	if ((Type == DRIVER_REQUEST)) {
		if (recv.size() > 0) {
			auto object = nlohmann::json::parse(recv);
			recv = Decompress(Decrypt(object["1"].get<std::string>(), "", key, iv));
		}
	}

	return recv;
}

std::string DemoFrame::NetworkWorker::Decrypt(std::string recvd, std::string token, std::string key, std::string iv) {
	std::string keys;
	if (token.empty() && key.empty() && iv.empty()) {
		keys = DemoFrame::Utils::CreateKey(Keypart1 + Keypart2);
	}
	else if (token.size() > 1) {
		keys = DemoFrame::Utils::CreateKey(token);
	}
	else {
		keys = key + iv;
	}
	return DemoFrame::cCryptInstance(DemoFrame::CRYPT_TYPE_DECRYPT, recvd, keys.substr(0, 32), keys.substr(32, 48)).Execute();
}

std::string DemoFrame::NetworkWorker::Decompress(std::string decrypted) {
	return DemoFrame::cCryptInstance(DemoFrame::CRYPT_TYPE_DECOMPRESS, decrypted).Execute();
}

nlohmann::json DemoFrame::NetworkWorker::CheckAction(std::string decompressed) {

	if (decompressed.size() > 0) {
		try {
			auto Return = nlohmann::json::parse(decompressed);
			static auto crash = CT_SPIN("abort");
			static auto true_Code = CT_SPIN("1");

			if (!Return[VMProtectDecryptStringA("wintag")].empty()) {
				DemoFrame::Utils::WriteSteamReg(Return[VMProtectDecryptStringA("wintag")].get<std::string>(), VMProtectDecryptStringA("MUID"));
			}

			if (!Return[VMProtectDecryptStringA("code")].empty() && Return[VMProtectDecryptStringA("code")].get<std::string>().compare("200")) {
			}

			if (!Return[VMProtectDecryptStringA("kill")].empty() && !Return[VMProtectDecryptStringA("kill")].get<std::string>().compare("1")) {
				TerminateProcess(nullptr, 200);
			}

			crash.decrypt();
			true_Code.decrypt();
			
			if (!Return[crash.get()].empty() && !Return[crash.get()].get<std::string>().compare(true_Code.get())) {
				
			}

			true_Code.encrypt();
			crash.encrypt();

			return Return;
		}catch(...){ }
	}

	return nlohmann::json();
}