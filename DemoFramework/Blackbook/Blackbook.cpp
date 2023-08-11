#include "../Includes/Frame-Include.h"
void ProjectBB::GlobalHandler::AddHandler(std::string _Name, ProjectBB::Handler<ReturnData(HandlerData*)> _Handler)
{
	std::unique_lock<std::mutex> lck(Sync);
	Handlers.emplace(std::move(_Name), std::move(_Handler));
	HasLast = true;
}

void ProjectBB::GlobalHandler::EraseHandler(std::string _Name) 
{
	std::unique_lock<std::mutex> lck(Sync);
	for (auto it = Handlers.begin(), end = Handlers.end(); it != end; ++it) 
	{
		if (it->first == _Name) 
		{
			Handlers.erase(it);
			HasLast = false;
			break;
		}
	}
}

auto ProjectBB::GlobalHandler::FindHandler(std::string _Name) -> Handler<ReturnData(HandlerData*)>&
{
	if (HasLast && Last.first == _Name)
		return Last.second;

	std::unique_lock<std::mutex> lck(Sync);
	for (auto it = Handlers.begin(), end = Handlers.end(); it != end;++it) 
	{
		if (it->first == _Name) 
		{
			HasLast = true;
			Last = (*it);
			return it->second;
		}
	}
}

ProjectBB::ReturnData ProjectBB::GlobalHandler::Invoke(std::string _Name, HandlerData & _Data)
{
	auto &Func = FindHandler(_Name);

	if (Func)
		return Func(&_Data);
}

ProjectBB::ReturnData ProjectBB::GlobalHandler::operator()(std::string & _Name, HandlerData & _Data)
{
	return Invoke(_Name, _Data);
}


void ProjectBB::Blackbook::Setup()
{


	static auto data = CT_SPIN("data");

	//call data from server and do auth
	EndUser.decrypt();
	std::string _UserAgent = Useragent[0] + " " + Useragent[1] + " " + Useragent[2] + EndUser.get();
	EndUser.encrypt();

	DemoFrame::NetworkWorker Worker = DemoFrame::NetworkWorker(Useragent[1], Useragent[2], _UserAgent);

	nlohmann::json Request = DemoFrame::Utils::GetUIDJSON(false);
	Dataid.decrypt();
	Request[Dataid.get()] = BuildID;
	Dataid.encrypt();

	Dataset.decrypt();
	URL.decrypt();
	auto Return = Worker.SendAPIRequest(Dataset.get(), Request);
	URL.encrypt();
	Dataset.encrypt();

	data.decrypt();
	try {
		Data = nlohmann::json::parse(Return[data.get()].get<std::string>());
	} catch(...){ }
	data.encrypt();
}

void ProjectBB::Blackbook::RegisterHandler(std::string _Table, Handler<ReturnData(HandlerData*)> _Function)
{
	HandlerList.AddHandler(std::move(_Table), std::move(_Function));
}

void ProjectBB::Blackbook::EraseHandler(std::string _Table)
{
	HandlerList.EraseHandler(_Table);
}

std::string ProjectBB::Blackbook::HandleCompression(std::string src) 
{
	std::replace(src.begin(), src.end(), '/', '_');
	return src;
}

ProjectBB::ReturnData ProjectBB::Blackbook::Invoke(std::string _Name, HandlerData & _Data, DemoFrame::CHeartBeat* Heartbeat)
{
	if (!Heartbeat) {
		Data.clear();
		return ReturnData("");
	}

	auto now = std::chrono::high_resolution_clock::now();
	auto difference = std::chrono::duration_cast<std::chrono::seconds> (now - Heartbeat->LastHeartbeatExecution);

	if (std::fabs(difference.count()) > 180)
	{
		Data.clear();
		return ReturnData(0);
	}
		
	
	return ReturnData(HandlerList.Invoke(_Name, _Data));
}

nlohmann::json& ProjectBB::Blackbook::WriteServerData()
{
	return Data;
}
