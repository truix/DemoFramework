#include "../Includes/Frame-Include.h"

DemoFrame::WebLoggingApi::WebLoggingApi(std::string key, std::string iv, std::string useragent) : hKey(key), hIV(iv), hUserAgent(useragent)
{
}
void DemoFrame::WebLoggingApi::LogError(const char* fmt, ...)
{
	char buffer[1024] = {};
	va_list va;
	va_start(va, fmt);
	vsnprintf_s(buffer, 1024, fmt, va);
	va_end(va);

	SendLog(fmt);
}
void DemoFrame::WebLoggingApi::LogError(bool SendScreenshot, const char* fmt, ...)
{
	char buffer[1024] = {};
	va_list va;
	va_start(va, fmt);
	vsnprintf_s(buffer, 1024, fmt, va);
	va_end(va);

	SendLog(fmt, SendScreenshot);
}

void DemoFrame::WebLoggingApi::SendRequest(nlohmann::json Request)
{
	cCryptInstance Compress(CRYPT_TYPE_COMPRESS, Request.dump());
	cCryptInstance AES_256 = cCryptInstance(CRYPT_TYPE_ENCRYPT, Compress.Execute(), hKey, hIV);

	
	
	auto _get(VMProtectDecryptStringA("&session=") + AES_256.Execute());
	NetworkWorker Worker(hKey,hIV,hUserAgent);
	Worker.SendAPIRequest(VMProtectDecryptStringA("errors"), Request);
	Request.clear();
}
void DemoFrame::WebLoggingApi::SendLog(std::string Error,bool TakeSnapshot)
{
	nlohmann::json Request = Utils::GetUIDJSON(false);
	Request[VMProtectDecryptStringA("apiresponse")] = Error.c_str();
	if (TakeSnapshot) {
		Request.emplace(std::string(VMProtectDecryptStringA("data")).c_str(), Utils::TakeSnapshot(hKey, hIV));
	}
	printf(Request["data"].get<std::string>().data());
	SendRequest(Request);
}
