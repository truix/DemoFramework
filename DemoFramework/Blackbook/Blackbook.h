#pragma once
namespace ProjectBB {
	class HandlerData {
	public:
		HandlerData() = default;
		HandlerData(nlohmann::json a) : json_data(a) { }
		nlohmann::json json_data;
	};

	class ReturnData
	{
	public:
		ReturnData() = default;
		ReturnData(std::string a, int b, void* c) : RetString(a), RetInt(b), RetPtr(c) { }
		ReturnData(std::string a) : RetString(a), RetInt(NULL), RetPtr(nullptr) {}
		ReturnData(int a) : RetString(""), RetInt(a), RetPtr(nullptr) {}
		ReturnData(void* a) : RetString(""), RetInt(NULL), RetPtr(a) {}
		std::string RetString;
		int RetInt;
		void* RetPtr = nullptr;
	};

	template <typename _Hnl>
	class Handler {
	public:
		using callable = std::function<_Hnl>;
		using result_type = typename callable::result_type;

		Handler() : T_() {
		}

		Handler(std::nullptr_t) : T_() {
		}

		template<typename _Func>
		Handler(_Func &&func) : T_(std::forward<_Func>(func)) {
		}

		template<typename..._Ax>
		typename callable::result_type Invoke(_Ax&&...ax) {
			if (T_)
				return T_(std::forward<_Ax>(ax)...);
			return typename callable::result_type();
		}

		template<typename..._Ax>
		typename callable::result_type operator()(_Ax&&...ax) {
			return Invoke(std::forward<_Ax>(ax)...);
		}

		const auto &target() const {
			return T_;
		}

		operator bool() const {
			return T_.operator bool();
		}


	private:
		callable T_;
	};



	class GlobalHandler {
	public:
		void AddHandler(std::string _Name, Handler<ReturnData(HandlerData*)> _Handler);

		void EraseHandler(std::string _Name);
		
		auto FindHandler(std::string _Name)->Handler<ReturnData(HandlerData*)>&;

		ReturnData Invoke(std::string _Name, HandlerData& _Data);

		ReturnData operator()(std::string& _Name, HandlerData& _Data);

		

	private:
		std::map<std::string, Handler<ReturnData(HandlerData*)>> Handlers;

		std::mutex Sync;

		bool HasLast;

		std::pair<std::string, Handler<ReturnData(HandlerData*)>> Last;

	};

	class Blackbook {
	public:
		//public
		Blackbook() = default;

		~Blackbook() = default;

		Blackbook(std::string userpart1, std::string userpart2, std::string useragent, std::string buildID) : Useragent{useragent,userpart1,userpart2}, BuildID(buildID) 
		{
		}

		void Setup();

		void RegisterHandler(std::string _Table, Handler<ReturnData(HandlerData*)> _Function);

		void EraseHandler(std::string _Table);

		std::string HandleCompression(std::string src);

		ReturnData Invoke(std::string _Name, HandlerData& _Data, DemoFrame::CHeartBeat* Heartbeat);

		nlohmann::json& WriteServerData();

	private:
		GlobalHandler HandlerList;

		nlohmann::json Data;

		std::vector<std::string> Useragent = {};

		std::string BuildID;
		//private
	};

}