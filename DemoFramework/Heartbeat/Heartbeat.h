#pragma once

namespace DemoFrame
{
	struct HeartBeatStatus
	{
		std::string LastFunction;
		std::string TimeStamp;
		ULONGLONG Time64;
		std::chrono::time_point<std::chrono::steady_clock> LastTime;
		HeartBeatStatus(std::string a, std::string b, ULONGLONG c, std::chrono::time_point<std::chrono::steady_clock> d)
		{
			LastFunction = a;
			TimeStamp = b;
			Time64 = c;
			LastTime = d;
		}
	};

	enum HeartbeatModes
	{
		HEARTBEAT_DEFAULT =    ( 1 << 0 ),
		HEARTBEAT_NONE =       ( 1 << 1 ),
		HEARTBEAT_DRIVERSCAN = ( 1 << 2 ),
		HEARTBEAT_REMOVED0 = ( 1 << 3 ),
		HEARTBEAT_REMOVED1 =    ( 1 << 4 ),
		HEARTBEAT_REMOVED2 =    ( 1 << 5 ),
		HEARTBEAT_REMOVED3 =    ( 1 << 6 ),
		HEARTBEAT_REMOVED4 =    ( 1 << 7 ),
	};


	class CHeartBeat
	{
	public:
		
		/**
		 * \brief Creates the Heartbeat class
		 * \param key First Part of the Useragent
		 * \param iv  Second Part of the Useragent
		 * \param useragent The Build name (aka front of the useragent)
		 * \param hbFlags if no flags set it will default to the platform prefered method
		 */
		CHeartBeat(std::string key, std::string iv, std::string useragent, int hbFlags = HEARTBEAT_DEFAULT);

		CHeartBeat(bool);

		void Heartbeat_wrapper(void*);

		std::string hIV, hKey, hUserAgent;

		std::chrono::time_point<std::chrono::steady_clock> Start, Current;

		void Sleep(int, int);

		std::vector<HeartBeatStatus> ReturnStatus();

		WebLoggingApi Logs;

		std::chrono::time_point<std::chrono::steady_clock> LastHeartbeatExecution = std::chrono::high_resolution_clock::now();
	private:
		NetworkWorker Worker;
		
		void HeartbeatThread();

		void SendPostHeartbeatInfo();

		void HandleHeartbeat();

		void KillProcess();

		int flags;

		nlohmann::json ResultJson;

		DriverScan Driver_Scan;

		bool bKillAfterHeartbeat = false;

		std::vector<HeartBeatStatus> Status;
	};
}
