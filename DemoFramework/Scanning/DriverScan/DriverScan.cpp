#include "../../Includes/Frame-Include.h"


bool DemoFrame::DriverScan::manual_invoke() {

	if (setup()) {
		run_scan();
		erase_data();
	}
	else {
		erase_data();
		return false;
	}
	return true;
}

nlohmann::json DemoFrame::DriverScan::get_drivers() {
	nlohmann::json drivers;
	static auto newdrivers = CT_SPIN("newdrivers");
	static auto forbidden = CT_SPIN("forbiddendrivers");

	RUNTIME_HANDLER(newdrivers, drivers[newdrivers.get()] = new_drivers;)
	RUNTIME_HANDLER(forbidden, drivers[forbidden.get()] = forbidden_drivers;)

	return drivers;
}

bool DemoFrame::DriverScan::close_forbidden() {
	std::vector<std::string> driverList;

	bool returnbuf = true;

	for (auto i = forbidden_drivers.begin(); i != forbidden_drivers.end(); ++i) {
		driverList.push_back((*i).get<std::string>().substr(0, (*i).get<std::string>().size() - 4));
	}

	for (auto& drv : driverList) {

		STARTUPINFO startupInfo = {};
		RtlSecureZeroMemory(&startupInfo, sizeof(STARTUPINFO));
		startupInfo.cb = sizeof(STARTUPINFO);

		PROCESS_INFORMATION processInfo = {};
		RtlSecureZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));

		TCHAR buf[MAX_PATH];
		sprintf_s< MAX_PATH>(buf, VMProtectDecryptStringA("net stop %s"), drv.data());

		if (!CreateProcess(nullptr, buf, nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE, nullptr, nullptr, &startupInfo, &processInfo)) {
			CloseHandle(processInfo.hProcess);
			returnbuf = false;
			continue;
		}

		if (WaitForSingleObject(processInfo.hProcess, INFINITE) != WAIT_OBJECT_0) {
			CloseHandle(processInfo.hProcess);
			returnbuf = false;
			continue;
		}

		DWORD exitCode = 0;
		if (GetExitCodeProcess(processInfo.hProcess, &exitCode) == 0) {
			CloseHandle(processInfo.hProcess);
			returnbuf = false;
			continue;
		}

		if (exitCode != ERROR_SUCCESS) {
			CloseHandle(processInfo.hProcess);
			system(buf);
			returnbuf = false;
			continue;
		}

		CloseHandle(processInfo.hProcess);
	}
	forbidden_drivers.clear();
	manual_invoke();

	if (forbidden_drivers.size() > 0)
		returnbuf = false;
	else
		returnbuf = true;

	return returnbuf;
}

void DemoFrame::DriverScan::erase_data() {
	if (!api_drivers.empty()) {
		api_drivers.clear();
	}

	if (!system_drivers.empty()) {
		system_drivers.clear();
	}
}

bool DemoFrame::DriverScan::get_state() {
	return driverstate;
}

bool DemoFrame::DriverScan::setup() {

	if (get_system_drivers()) {
		if (get_api_drivers()) {
		}
		else {
			//log error
			api_drivers.clear();
			system_drivers.clear();
			return false;
		}
	}
	else {
		//log error
		system_drivers.clear();
		return false;
	}
	return true;
}

bool DemoFrame::DriverScan::get_api_drivers() {
	try {
		auto url = CT_SPIN("https://cdn.Demo");


		RUNTIME_HANDLER(key, RUNTIME_HANDLER(iv, RUNTIME_HANDLER(url, RUNTIME_HANDLER(loc,
						result_json = Worker.SendDriverRequest(url.get(), loc.get(), key.get(), iv.get());
		))))
		
			nlohmann::json json;
		auto drivstr = CT_SPIN("drivers");

		RUNTIME_HANDLER(drivstr, json = result_json[drivstr.get()];)

			api_drivers.clear();
		int driversize = 0;
		auto drvsize = CT_SPIN("driverssize");
		RUNTIME_HANDLER(drvsize, driversize = result_json[drvsize.get()].get<int>() - 1;)
			static auto name = CT_SPIN("name");
		static auto forbidden = CT_SPIN("forbidden");
		for (auto i = 0; i < driversize; i++) {
			RUNTIME_HANDLER(name, RUNTIME_HANDLER(forbidden,
							auto subarray = json[i];
			api_drivers.emplace(subarray[name.get()].get<std::string>(), subarray[forbidden.get()].get<std::string>());
			))
		}

	}
	catch (...) {
		return false;
	}
	return true;
}

bool DemoFrame::DriverScan::get_system_drivers() {
	VMProtectBeginMutation("DRIVERSCAN_GETDRIVERS");
	LPVOID drivers[1024];
	DWORD cb_needed;

	if (EnumDeviceDrivers(drivers, sizeof drivers, &cb_needed) && cb_needed < sizeof drivers) {
		TCHAR szDriver[1024];
		TCHAR szDriverwp[2048];
		int cDrivers = cb_needed / sizeof drivers[0];

		for (auto i = 0; i < cDrivers; i++) {
			if (GetDeviceDriverBaseNameA(drivers[i], szDriver, sizeof szDriver / sizeof szDriver[0])) {
				if (GetDeviceDriverFileNameA(drivers[i], szDriverwp, sizeof szDriverwp / sizeof szDriverwp[0])) {
					if (szDriver != "")
						system_drivers.emplace(szDriver, Scanner.GetSignerInformation(szDriverwp)[0]);
				}
			}
		}
	}
	else {
		return false;
	}

	VMProtectEnd();
	return true;
}

bool DemoFrame::DriverScan::run_scan() {
	VMProtectBeginMutation("DriverScan");

	try {
		for (auto i : system_drivers) {
			//check if we found driver in api-list
			if (api_drivers[i.first].size() != 0) {
				//check if driver is forbidden
				if (!api_drivers[i.first].compare("1")) {
					forbidden_drivers[i.first] = i.second;
					//kill after we send drivers
					driverstate = true;
				}
			}
			else {
				//driver didn't exist, so add it
				new_drivers[i.first] = i.second;
				//check if we should kill if we find new drivers
				static auto strict = CT_SPIN("strictmode");
				RUNTIME_HANDLER(strict,
								if (result_json[strict.get()].get<std::string>() == ("1")) {
									//kill after scan
									driverstate = true;
								}
				)
			}
		}
	}
	catch (...) {
		driverstate = true;
		return driverstate;
	}

	return driverstate;
	VMProtectEnd();
}
