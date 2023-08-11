
namespace DemoFrame
{
	class WebLoggingApi
	{
	public:
		WebLoggingApi() {}
		WebLoggingApi(std::string, std::string, std::string);
		void LogError(const char*fmt, ...);

		void LogError(bool SendSnapshot = false, const char* fmt = "", ...);

	private:
		void SendRequest(nlohmann::json);
		void SendLog(std::string, bool = false);
		std::string hKey, hIV, hUserAgent;
	};
}
