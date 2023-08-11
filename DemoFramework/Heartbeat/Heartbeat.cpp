#include "../Includes/Frame-Include.h"


DemoFrame::CHeartBeat::CHeartBeat(std::string key, std::string iv, std::string useragent, int hbFlags)
{
	if (hbFlags & HEARTBEAT_DEFAULT) {
		flags = HEARTBEAT_DRIVERSCAN ;
	}
	else {
		flags = hbFlags;
	}
	hUserAgent = useragent + " " + key + " " + iv + VMProtectDecryptStringA(" Windows NT WOW64");
	Worker = NetworkWorker(key, iv, hUserAgent);
	auto KeyDelta = Utils::CreateKey(key + iv);
	hKey = KeyDelta.substr(0, 32);
	hIV = KeyDelta.substr(32, 48);
	Logs = WebLoggingApi(key, iv, hUserAgent);
	Driver_Scan = DriverScan(hUserAgent);
}

DemoFrame::CHeartBeat::CHeartBeat(bool Kill)
{
	if (Kill)
	{
		Logs.LogError(VMProtectDecryptStringA("Manual Kill Called"));
		this->KillProcess();
	}
}

void DemoFrame::CHeartBeat::Heartbeat_wrapper(void*)
{
	

	HeartbeatThread();
}

void DemoFrame::CHeartBeat::HeartbeatThread()
{
	while (true)
	{
		Start = std::chrono::high_resolution_clock::now();
		Status.push_back({ VMProtectDecryptStringA("HBTS"), Utils::getTimeStamp(), GetTickCount64(),std::chrono::high_resolution_clock::now() });
		Utils::ScanHostFileForSpoofing();

		this->HandleHeartbeat();
		if (Utils::IsRunningInSafeMode())
		{
			Logs.LogError(VMProtectDecryptStringA("Running in safe mode"));
			exit(0);
		}

		if ( Utils::IsTestSigningEnabled())
		{
			Logs.LogError(VMProtectDecryptStringA("DSE is off"));
			exit(0);
		}

	

		Status.push_back({ VMProtectDecryptStringA("HBTE"), Utils::getTimeStamp(), GetTickCount64(),std::chrono::high_resolution_clock::now() });

		auto difference = std::chrono::duration_cast<std::chrono::milliseconds> (std::chrono::high_resolution_clock::now() - Start);
		Sleep(60, -difference.count());
	}
}

void DemoFrame::CHeartBeat::SendPostHeartbeatInfo()
{
	Status.push_back({ VMProtectDecryptStringA("SFD"), Utils::getTimeStamp(), GetTickCount64(),std::chrono::high_resolution_clock::now() });

	try
	{
		nlohmann::json Request = nlohmann::json::merge(Driver_Scan.get_drivers(), Utils::GetUIDJSON(true));

		Request[VMProtectDecryptStringA("state")] = cCryptInstance(std::to_string(flags)).Execute();


		if (!Request.empty())
		{
			Worker.SendAPIRequest(VMProtectDecryptStringA("heartbeat"), Request);
		}
	}
	catch (...) {}
}

std::mutex ThreadSaftey;
std::vector<DemoFrame::HeartBeatStatus> DemoFrame::CHeartBeat::ReturnStatus()
{
	std::lock_guard<std::mutex> Lock(ThreadSaftey);
	return Status;
}

void DemoFrame::CHeartBeat::HandleHeartbeat()
{
	VMProtectBeginMutation ("FRAME_Heartbeat");

	if (Status.size() > 128)
		Status.clear();
	
	Status.push_back({ VMProtectDecryptStringA("HBS"), Utils::getTimeStamp(), GetTickCount64(),std::chrono::high_resolution_clock::now() });


	nlohmann::json Request = Utils::GetUIDJSON(true);

	Request[VMProtectDecryptStringA("state")] = cCryptInstance(std::to_string(flags)).Execute();

	ResultJson = Worker.SendAPIRequest(VMProtectDecryptStringA("Heartbeat"), Request);

	Request.clear();

	
	if (ResultJson[VMProtectDecryptStringA("code")].empty() || ResultJson[VMProtectDecryptStringA("code")].get<std::string>().compare(VMProtectDecryptStringA("200")) &&
		ResultJson[VMProtectDecryptStringA("kill")].empty() || ResultJson[VMProtectDecryptStringA("kill")].get<std::string>().compare(VMProtectDecryptStringA("0")))
	{
		this->KillProcess();
	}

	ResultJson.clear();


	if (flags & HEARTBEAT_DRIVERSCAN)
		Driver_Scan.manual_invoke();

	if (Driver_Scan.get_state())
		bKillAfterHeartbeat = true;

	SendPostHeartbeatInfo();

	if (bKillAfterHeartbeat)
	{
		this->KillProcess();
		exit(0);
	}


	ResultJson.clear();
	Status.push_back({ VMProtectDecryptStringA("HBE"), Utils::getTimeStamp(), GetTickCount64(),std::chrono::high_resolution_clock::now() });
	LastHeartbeatExecution = std::chrono::high_resolution_clock::now();
	VMProtectEnd();
}

void DemoFrame::CHeartBeat::KillProcess()
{
	exit(EXIT_SUCCESS);
	int* p = nullptr;
	*p = 1;
}

void DemoFrame::CHeartBeat::Sleep(int Seconds, int Miliseconds)
{
	std::this_thread::sleep_for(std::chrono::milliseconds(Seconds * 1000 + Miliseconds));
}
