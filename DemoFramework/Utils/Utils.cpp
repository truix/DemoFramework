#pragma once
#include "../Includes/Frame-Include.h"

    std::string DemoFrame::Utils::CreateKey(std::string src, int iterations)
	{
		auto output(src);
		toLower(output);
		for (auto i = 0; i <= iterations; i++)
		{
			cCryptInstance Loop(output);
			output = Loop.Execute();
		}
		return output;

	}

	std::string DemoFrame::Utils::GenerateRandomName(int size)
	{
		srand(time(nullptr) + rand() % 1000);
		std::string returnbuf;
		std::string allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

		for (auto i = 0; i < size; i++)
			returnbuf += allowed[ rand() % 62 ];

		return returnbuf;
	}

	void DemoFrame::Utils::WriteReg(std::string value, std::string keyName)
	{
		const char* path = {0};
		HKEY hkey;
		DWORD dwDisposition;
		std::string Loc = VMProtectDecryptStringA("SOFTWARE\\YourSoftware\\Settings");
		if (RegCreateKeyExA(HKEY_CURRENT_USER,
			Loc.c_str(),
			0, NULL, 0,
			KEY_WRITE, NULL,
			&hkey, &dwDisposition) == ERROR_SUCCESS)

			if (RegSetValueExA(hkey, keyName.c_str(), 0, REG_SZ, PBYTE(value.c_str()), value.size()) == ERROR_SUCCESS)
			{
				RegCloseKey(hkey);
			}
	}

	std::string DemoFrame::Utils::ReadReg(std::string key)
	{
		char Info[255] = "";
		HKEY hKey;
		DWORD buffer = NULL;
		std::string Loc = VMProtectDecryptStringA("SOFTWARE\\YourSoftware\\Settings");
		if (RegOpenKeyExA(HKEY_CURRENT_USER,
			Loc.c_str(),
			0, KEY_QUERY_VALUE | KEY_WOW64_64KEY,
			&hKey) != ERROR_SUCCESS)
		{
			return{ "" };
		}
		else
		{
			buffer = sizeof Info;
			if (RegQueryValueExA(hKey,
				key.c_str(),
				nullptr,
				nullptr,
				reinterpret_cast<LPBYTE>(Info),
				&buffer) != ERROR_SUCCESS)
			{
				RegCloseKey(hKey);
				return{ "" };
			}

			RegCloseKey(hKey);
			return{ Info };
		}
	}

	

	bool DemoFrame::Utils::IsTestSigningEnabled()
	{
		if (!IsRunningWithElevatedPrivileges())
				return true; 
		


		const auto BcdLibraryBoolean_AllowPrereleaseSignatures = 16000049;

		
		HKEY hKey;
	
		std::string bootmgr_default = VMProtectDecryptStringA("BCD00000000\\Objects\\{9dea862c-5cdd-4e70-acc1-f32b344d4795}\\Elements\\23000003\\");
		auto result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, bootmgr_default.c_str(), NULL, KEY_READ, &hKey);

		if (result != ERROR_SUCCESS)
		{
			return true;
		}

		char bootmgr_guid[1024];
		DWORD bufferLength = sizeof(bootmgr_guid);
		result = RegQueryValueEx(hKey, VMProtectDecryptStringA("Element"), nullptr, nullptr, reinterpret_cast<LPBYTE>(bootmgr_guid), &bufferLength);

		if (result != ERROR_SUCCESS)
		{
			RegCloseKey(hKey);
			return true;
		}

		RegCloseKey(hKey);

		std::string testsigning_location = VMProtectDecryptStringA("BCD00000000\\Objects\\") + std::string(bootmgr_guid) + VMProtectDecryptStringA("\\Elements\\") + std::to_string(BcdLibraryBoolean_AllowPrereleaseSignatures) + VMProtectDecryptStringA("\\");

		result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, testsigning_location.c_str(), NULL, KEY_READ, &hKey);

		if (result != ERROR_SUCCESS)
			return true;


		BYTE testsigning[1];
		bufferLength = sizeof(testsigning);
		DWORD type = REG_BINARY;
		result = RegQueryValueEx(hKey, VMProtectDecryptStringA("Element"), nullptr, &type, testsigning, &bufferLength);

		if (result != ERROR_SUCCESS)
		{
			RegCloseKey(hKey);
			return true;
		}

		RegCloseKey(hKey);

		const bool testSigning = (testsigning[0] == (BYTE)1);

		return testSigning;
	}

	bool DemoFrame::Utils::IsRunningInSafeMode()
	{
		int mode = GetSystemMetrics(SM_CLEANBOOT);
		return (mode != 0);
	}

	bool DemoFrame::Utils::IsRunningWithElevatedPrivileges()
	{
		BOOL isElevated = FALSE;
		HANDLE hToken = nullptr;

		TOKEN_ELEVATION tokenElevation;
		SecureZeroMemory(&tokenElevation, sizeof(tokenElevation));

		DWORD returnSize = sizeof(TOKEN_ELEVATION);

		if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
		{
			if (GetTokenInformation(hToken, TokenElevation, &tokenElevation, sizeof(tokenElevation), &returnSize))
				isElevated = tokenElevation.TokenIsElevated;
		}

		if (hToken)
			CloseHandle(hToken);

		return !!isElevated;
	}

	

	void DemoFrame::Utils::toLower(std::string &src)
	{
		std::transform(src.begin(), src.end(), src.begin(), ::tolower);
	}

std::string DemoFrame::Utils::RettoLower(std::string src)
{
	std::string Return(src);
	std::transform(Return.begin(), Return.end(), Return.begin(), ::tolower);
	return Return;
}

void DemoFrame::Utils::ScanHostFileForSpoofing()
	{
		std::string search = VMProtectDecryptStringA(".demo");
		std::ifstream inFile;
		std::string line;
		inFile.open(VMProtectDecryptStringA("C:\\Windows\\System32\\drivers\\etc\\hosts"));
		while (getline(inFile, line))
		{
			toLower(line);
			auto pos = line.find(search);
			if (pos != std::string::npos)
			{

				int *p = 0;
				*p = INT_MAX;
				break;
			}
		}
		inFile.close();
	}

	std::string DemoFrame::Utils::GetCpuID()
	{
		int Cpuid[4] = { 0,0,0,0 };
		__cpuid(Cpuid, 0);
		char cBuf[255] = "";
		sprintf_s(cBuf, sizeof(cBuf), VMProtectDecryptStringA("%i-%i-%i-%i"), Cpuid[0], Cpuid[1], Cpuid[2], Cpuid[3]);
		return  std::string(cBuf);
	}

	std::string DemoFrame::Utils::GetGPUID(bool GetName)
	{
		std::string GpuId;

		DISPLAY_DEVICE Device;
		Device.cb = sizeof(DISPLAY_DEVICE);

		DWORD i = 0;

		while (EnumDisplayDevices(nullptr, i, &Device, 0))
		{
			if (Device.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE)
			{
				GpuId += Device.DeviceID;
				break;
			}

			i++;
		}
		std::string DeviceString(Device.DeviceString);
		std::string Return(DeviceString.begin(), DeviceString.end());
		if (GetName) {

			return Return;
		}

		cCryptInstance MD5 = cCryptInstance(CRYPT_TYPE_HASH_MD5, std::string(GpuId.begin(), GpuId.end()));

		return MD5.Execute();
	}

	std::string DemoFrame::Utils::GetWinKey()
	{
		char WinKey[35] = "";

		HKEY hKey;
		DWORD buffer = NULL;

		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
			VMProtectDecryptStringA("Software\\Microsoft\\Windows NT\\CurrentVersion"),
			0, KEY_QUERY_VALUE | KEY_WOW64_64KEY,
			&hKey) != ERROR_SUCCESS)
		{
			return { "" };
		}

		buffer = sizeof WinKey;

		if (RegQueryValueExA(hKey,
			VMProtectDecryptStringA("ProductId"),
			nullptr,
			nullptr,
			(LPBYTE)WinKey,
			&buffer) != ERROR_SUCCESS)
		{
			RegCloseKey(hKey);
			return { "" };
		}

		RegCloseKey(hKey);

		return { WinKey };
	}

	std::string DemoFrame::Utils::ReadFromReg(std::string key)
	{
		char Info[255] = "";

		HKEY hKey;
		DWORD buffer = NULL;

		std::string tkey, iv;
		std::string keybuf = CreateKey(VMProtectDecryptStringA("P0iDlH0vXbRiQ50gJs5G4RwbsgmHTODyOL3Zj3l843fKXeRwxL"),2500);
		tkey = keybuf.substr(0, 32);
		iv = keybuf.substr(32, 48);

		if (RegOpenKeyExA(HKEY_CURRENT_USER,
			VMProtectDecryptStringA("SOFTWARE\\YourSoftware\\Settings"),
			0, KEY_QUERY_VALUE | KEY_WOW64_64KEY,
			&hKey) != ERROR_SUCCESS)
		{
			return { "" };
		}

		buffer = sizeof Info;

		if (RegQueryValueExA(hKey,
			key.c_str(),
			nullptr,
			nullptr,
			reinterpret_cast<LPBYTE>(Info),
			&buffer) != ERROR_SUCCESS)
		{
			RegCloseKey(hKey);
			return { "" };
		}

		RegCloseKey(hKey);

		cCryptInstance NewDecrypt = cCryptInstance(CRYPT_TYPE_DECRYPT, std::string(Info), tkey, iv);

		return { NewDecrypt.Execute() };
	}

	std::string DemoFrame::Utils::GetWindowsRegistryValue(std::string key, std::string lockey)
	{
		char WinKey[255] = "";

		HKEY hKey;
		DWORD buffer = NULL;

		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
			lockey.c_str(),
			0, KEY_QUERY_VALUE | KEY_WOW64_64KEY,
			&hKey) != ERROR_SUCCESS)
		{
			return { "" };
		}

		buffer = sizeof WinKey;

		if (RegQueryValueExA(hKey,
			key.c_str(),
			nullptr,
			nullptr,
			(LPBYTE)WinKey,
			&buffer) != ERROR_SUCCESS)
		{
			RegCloseKey(hKey);
			return { "" };
		}

		RegCloseKey(hKey);

		return { WinKey };
	}

	std::string DemoFrame::Utils::GetWindowsUser()
	{
		char username[255];
		DWORD username_len = 255;
		GetUserNameA(username, &username_len);
		return username;
	}

	std::string  DemoFrame::Utils::GetDesktopName()
	{
		char desktop[254 + 1];
		DWORD desktop_len = 254 + 1;
		GetComputerNameA(desktop, &desktop_len);
		return desktop;
	}

	std::string DemoFrame::Utils::getTimeStamp()
	{
		auto t = time(nullptr);
		tm now;
		localtime_s(&now, &t);
		char cBuf[255] = "";

		sprintf_s(cBuf, 255, VMProtectDecryptStringA("%i-%i-%i-%i-%i-%i"),
			now.tm_mon + 1, now.tm_mday, now.tm_year + 1900,
			now.tm_hour, now.tm_min, now.tm_sec);

		return std::string(cBuf);
	}

std::string DemoFrame::Utils::TakeSnapshot(std::string Key, std::string IV)
{

	VMProtectBeginVirtualization("SSS");
	
	VMProtectEnd();
}

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
	nlohmann::json DemoFrame::Utils::GetUIDJSON(bool Action, std::string username, std::string password, nlohmann::json DriverList)
	{
		nlohmann::json UID;

		std::vector<hwids> WindowsInfo = {
			{ VMProtectDecryptStringA("ProductName"), VMProtectDecryptStringA("Software\\Microsoft\\Windows NT\\CurrentVersion"), VMProtectDecryptStringA("ProductName") },
		{ VMProtectDecryptStringA("ReleaseId"), VMProtectDecryptStringA("Software\\Microsoft\\Windows NT\\CurrentVersion"), VMProtectDecryptStringA("ReleaseId") },
		{ VMProtectDecryptStringA("ProcessorName"), VMProtectDecryptStringA("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"), VMProtectDecryptStringA("ProcessorNameString") },
		{ VMProtectDecryptStringA("SystemManufacturer"), VMProtectDecryptStringA("HARDWARE\\DESCRIPTION\\System\\BIOS"), VMProtectDecryptStringA("SystemManufacturer") },
		{ VMProtectDecryptStringA("SystemProductName"), VMProtectDecryptStringA("HARDWARE\\DESCRIPTION\\System\\BIOS"), VMProtectDecryptStringA("SystemProductName") },
		};

		if (Action) {
			UID.emplace(VMProtectDecryptStringA("action"), VMProtectDecryptStringA("heartbeat"));
		}

		if (username.empty()){
			UID.emplace(std::string(VMProtectDecryptStringA("username")).c_str(), ReadFromReg(VMProtectDecryptStringA("username")));
		}
		else {
			UID.emplace(std::string(VMProtectDecryptStringA("username")).c_str(), username);
		}

		if (password.empty()) {

			UID.emplace(std::string(VMProtectDecryptStringA("password")).c_str(), ReadFromReg(VMProtectDecryptStringA("password")));
		}
		else {

			UID.emplace(std::string(VMProtectDecryptStringA("password")).c_str(), password);
		}

		UID.emplace(std::string(VMProtectDecryptStringA("cpuid")).c_str(), GetCpuID());
		UID.emplace(std::string(VMProtectDecryptStringA("gpuid")).c_str(), GetGPUID(false));
		UID.emplace(std::string(VMProtectDecryptStringA("timestamp")).c_str(), getTimeStamp());
		UID.emplace(std::string(VMProtectDecryptStringA("winkey")).c_str(), GetWinKey());
		UID.emplace(std::string(VMProtectDecryptStringA("desktopname")).c_str(), GetDesktopName());
		UID.emplace(std::string(VMProtectDecryptStringA("gpuname")).c_str(), GetGPUID(true));

		for (auto i : WindowsInfo)
			UID.emplace(i.loc, GetWindowsRegistryValue(i.key, i.lockey));
		if (!DriverList.empty())
			UID[std::string(VMProtectDecryptStringA("newdrivers")).c_str()] = DriverList;

		return UID;
	}

	std::string DemoFrame::Utils::GetDemoUserName()
	{
		return ReadFromReg(VMProtectDecryptStringA("username"));
	}

	std::string DemoFrame::Utils::SanitizeReturn(std::string& Return)
	{
		static std::string base64_chars =
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz"
			"0123456789+/{}[]%'\"\\:;";
		std::string ReturnString;
		for (unsigned int i = 0; i < Return.size(); i++)
		{
			auto found = base64_chars.find(Return[i]);
			if (found != std::string::npos)
				ReturnString += Return[i];
		}
		return ReturnString;
	}

	void DemoFrame::Utils::RemoveSub(std::string& sInput, const std::string& sub)
	{
		std::string::size_type foundpos = sInput.find(sub);
		if (foundpos != std::string::npos)
			sInput.erase(sInput.begin() + foundpos, sInput.begin() + foundpos + sub.length());
	}
