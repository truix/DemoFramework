

#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <windows.h>
#include <IOSTREAM>
#include <string>
#include <Psapi.h>
#include <lmcons.h>
#include <algorithm>
#include <vector>
#include <shlobj.h>
#include <time.h>
#include <random>
#include <sstream>
#include <fstream>
#include <shlwapi.h>
#include <iomanip>
#include <ctime>
#include <array>
#include <intrin.h>
#include <iphlpapi.h>
#include <process.h>
#include <Memory>
#include <chrono>
#include <thread>
#include <atlstr.h>
#include <WMIUtils.h>
#include <wmistr.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <gdiplus.h>
#include <atlimage.h>
#include <comutil.h>
#include <locale>
#include <io.h>
#include <Fcntl.h>
#include <tlhelp32.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <string>
//#include <any>
#include <psapi.h>
#include <time.h>
#include <process.h>
#include <vector>
#include <map>
#include <ostream>
#include <Shlobj.h>
#include <math.h>
#include <stdint.h>
#include <string>
#include <string.h>
#include <cmath>
#include <float.h>
#include <codecvt>
#include <cctype>
#include <Setupapi.h>
#include <limits>
#include <iso646.h>
#include <valarray>
#include <forward_list>
#include <numeric>
#include <clocale>
#include <Powerbase.h>
#include <Winternl.h>
#include <D3Dcompiler.h>
#include <WinTrust.h>
#include <tchar.h>
#include <filesystem>
#include <regex>

#pragma comment(lib, "mpr.lib")
#pragma comment(lib,"Winmm.lib")
#pragma comment (lib,"Gdiplus.lib")
#pragma comment(lib, "ComCtl32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment (lib, "ws2_32.lib" )
#pragma comment(lib,"Comctl32.lib")
#pragma comment(lib, "wininet")
#pragma comment( lib, "Msimg32" )
#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "Dbghelp.lib")
#pragma comment (lib, "urlmon.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Wldap32.lib")
#pragma comment (lib, "crypt32")
#pragma comment(lib,"psapi.lib")
#pragma comment (lib, "d3dcompiler.lib")
#pragma comment(lib,"PowrProf.lib")
#pragma comment(lib,"Normaliz.lib")
//Crypto pp
#include "../../CryptoPP/cryptlib.h"
#include "../../CryptoPP/aes.h"
#include "../../CryptoPP/pwdbased.h"
#include "../../CryptoPP/sha.h"
#include "../../CryptoPP/modes.h"
#include "../../CryptoPP/filters.h"
#include "../../CryptoPP/base64.h"
#include "../../CryptoPP/hex.h"
#include "../../CryptoPP/osrng.h"
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "../../CryptoPP/md5.h"
#include "../../CryptoPP/gzip.h"
#pragma comment (lib,"cryptlib.lib")
#pragma comment (lib,"ntdll.lib")
//curl
#define CURL_DISABLE_LDAP
#define HTTP_ONLY
#define CURL_STATICLIB

#ifdef NDEBUG
#include "C:/Developer/Sync/libcurl/x86/release/include/curl.h"
#pragma comment(lib,"C:/Developer/Sync/libcurl/x86/release/lib/libcurl_a.lib")
#else
#include "C:/Developer/Sync/libcurl/x86/debug/include/curl.h"

#pragma comment(lib,"C:/Developer/Sync/libcurl/x86/debug/lib/libcurl_a_debug.lib")
#endif

typedef unsigned(__stdcall *PTHREAD_START)(void*);
#define _BEGINTHREAD( x ) _beginthreadex(nullptr, 0, (PTHREAD_START)x, nullptr, 0, nullptr);//use this instead to create threads/ doesnt have a memory leak

typedef struct _PROCESSOR_POWER_INFORMATION {
	ULONG Number;
	ULONG MaxMhz;
	ULONG CurrentMhz;
	ULONG MhzLimit;
	ULONG MaxIdleState;
	ULONG CurrentIdleState;
} PROCESSOR_POWER_INFORMATION, *PPROCESSOR_POWER_INFORMATION;

//Framework Includes
#include "../Encryption/FrameworkStringEncryption.h"
#include "../ModuleSecurity/ModuleSecurity.h"
#include "../Encryption/Encryption.h"
#include "../JSON/JSON.h"
#include "../Scanning/DigitalCertificates/DigiCert.h"
#include "../Utils/Utils.h"
#include "../Fail-Safes/FailSafe.h"
#include "../Networking/Network.h"
#include "../Scanning/DriverScan/DriverScan.h"
#include "../Logging/Logging.h"
#include "../Heartbeat/Heartbeat.h"
#include "../../VMProtect/VMProtectSDK.h"
#include "../Hooking/VMT.h"
#include "../Blackbook/Blackbook.h"