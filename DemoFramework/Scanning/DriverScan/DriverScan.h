#pragma once
namespace DemoFrame {
	class DriverScan {
	public:
		DriverScan() = default;

		DriverScan( std::string UserAgent): Useragent(UserAgent)
		{
		}

		~DriverScan() = default;

		bool manual_invoke();
		bool get_state();
		nlohmann::json get_drivers();
		bool close_forbidden();
	private:
		DemoFrame::DigitalCertificateScanner Scanner;
		void erase_data();
		bool setup();
		bool get_api_drivers();
		bool get_system_drivers();

		bool run_scan();
		bool driverstate = false;

		std::string Useragent;
		std::unordered_map<std::string, std::string> system_drivers, api_drivers;
		nlohmann::json new_drivers, forbidden_drivers, result_json;
	};
}