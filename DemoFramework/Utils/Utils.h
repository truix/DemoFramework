#pragma once
namespace DemoFrame
{
	class Utils
	{
	public:
		/*Key Generation function for api communication, or to generate a key from a shared secret*/
		static std::string CreateKey(std::string src, int iteration = 2000);

		/*Generates a random string seeded from the time invoked*/
		static std::string GenerateRandomName(int size = 32);

		/*Write to Demo Registry Directory*/
		static void WriteReg(std::string value, std::string keyName);

		/*Read value from Demo Registry Directory*/
		static std::string ReadReg(std::string key);



		/*Check if TestSigning is enabled on target machine*/
		static bool IsTestSigningEnabled();

		/*Check if target machine is in Safe Mode*/
		static bool IsRunningInSafeMode();

		/*Check to see if host process has elevated privileges*/
		static bool IsRunningWithElevatedPrivileges();


		/*Convert string passed in to all lowercase*/
		static void toLower(std::string &src);

		/*Return Passed string to all lowercase*/
		static std::string RettoLower(std::string src);

		/*Check to see if host file has been tampered with*/
		static void ScanHostFileForSpoofing();

		/*Get CPUID **Not the serial number** */
		static std::string GetCpuID();

		/*Get GPU ID **Not the serial number** */
		static std::string GetGPUID(bool GetName);

		/*Get Windows Product Key*/
		static std::string GetWinKey();

		/*Read from Demo Registry Directory and decrypt*/
		static std::string ReadFromReg(std::string key);

		/*Read any Value In windows Registry under LOCAL_MACHINE*/
		static std::string  GetWindowsRegistryValue(std::string key, std::string lockey);

		/*Get Windows User Name*/
		static std::string GetWindowsUser();

		/*Get Desktop name*/
		static std::string  GetDesktopName();

		/*Get Current Timestamp*/
		static std::string getTimeStamp();

		/*Take a screenshot of all moniters on machine and encrypt*/
		static std::string TakeSnapshot(std::string key, std::string iv);

		struct hwids
		{
			hwids() {};
			hwids(std::string _loc, std::string _lockey, std::string _key)
			{
				loc = _loc;
				key = _key;
				lockey = _lockey;
			}
			std::string loc;
			std::string key;
			std::string lockey;
		};

		/*Get All hardware identifiers Demo uses*/
		static nlohmann::json GetUIDJSON(bool Action, std::string username = "", std::string password= "", nlohmann::json DriverList = nlohmann::json());

		/*Return Demo platform name*/
		static std::string GetDemoUserName();

		/*Santize base64 strings*/
		static std::string SanitizeReturn(std::string& Return);

		/*Remove subsection of a string*/
		void static RemoveSub(std::string& sInput, const std::string& sub);
	};
};