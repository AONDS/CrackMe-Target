#include "js.h"
#include "protect.h"

#if !defined(VERIFY_LIB) || defined(VERIFY_TEST)
namespace js
{
	int APP_ID = 0;
	int APP_VERSION = 0;
	int BUSINESS_SUCCESS_CODE = 0;
	const char* NOTICE_ID = "";
	const char* VAR_ID = "";
	const char* API_KEY = "";
	const char* SERVER_X25519_PUBLIC_KEY = "";
	const char* SERVER_ED25519_PUBLIC_KEY = "";

	extern "C" void init()
	{
		VERIFY_STR_BEGIN;
		APP_ID = 3766;
		APP_VERSION = 1;
		BUSINESS_SUCCESS_CODE = 1;
		NOTICE_ID = "2067";
		VAR_ID = "2074";
		API_KEY = "0bd3317d2be5b2264bc33d0aef7d25602dd2f0e444cedc7963be9ea01aaa906d";
		SERVER_X25519_PUBLIC_KEY = "a0cff91f3ebcc90eb3c1b09604756489542f379df321369f8036566f19708263";
		SERVER_ED25519_PUBLIC_KEY = "30918a7669c584e5eb358c7525d891d05057db4a0a58600bd199c8f7866d7212";
		VERIFY_STR_END;
	}
}
#ifndef VERIFY_TEST
#pragma comment(lib,"JsVerify.lib")
#endif
#endif