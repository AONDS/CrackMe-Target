#ifndef VERIFY_JS_H
#define VERIFY_JS_H

#include <ctime>
#include <atomic>
#include <string>
#include <vector>
#include <windows.h>

namespace js
{
	struct Notice
	{
		std::string type;
		std::string title;
		std::string content;
	};
	using Notices = std::vector<Notice>;

	struct Var
	{
		enum
		{
			_i,
			_d,
			_s
		};
		int type{ _i };
		int i{};
		double d{};
		std::string s;
		std::string name;
	};
	using Vars = std::vector<Var>;

	struct Update
	{
		int ver = 0;
		bool force = false;
		std::string title;
		std::string content;
	};

	struct Query
	{
		bool disable = false;
		bool online = false;
		int unbind_count = 0;
		time_t activate = 0;
		time_t expired = 0;
	};

	extern int APP_ID;
	extern int APP_VERSION;
	extern int BUSINESS_SUCCESS_CODE;
	extern const char* NOTICE_ID;
	extern const char* VAR_ID;
	extern const char* API_KEY;
	extern const char* SERVER_X25519_PUBLIC_KEY;
	extern const char* SERVER_ED25519_PUBLIC_KEY;

	extern "C" bool notice(Notices& notices);
	extern "C" bool update(Update& update);
	extern "C" bool query(const std::string& card, Query& query);
	extern "C" bool login(const std::string& card, HANDLE& thread, std::atomic<time_t>*& heart_clock);
	// Process-local authorization lease; checks verified heartbeat and real worker handle.
	extern "C" bool session_valid();
	extern "C" bool var(Vars& vars);
	extern "C" bool unbind(const std::string& card);
	extern "C" void init();
}

#endif