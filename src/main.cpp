#include "protect.h"
#include "js.h"
#include <iostream>
#include <sstream>

#ifdef VERIFY_TEST

int main()
{
	using namespace std;
	std::locale::global(std::locale(".UTF8"));
	SetConsoleOutputCP(CP_UTF8);

	js::init();

	string key = "TEST_QP_XXX";

	cout << "#公告" << endl;
	js::Notices nti;
	if (js::notice(nti))
	{
		for (const auto& i : nti)
		{
			cout << "type: " << i.type << endl;
			cout << "title: " << i.title << endl;
			cout << "content: " << i.content << endl;
			puts("\n");
		}
	}
	else
	{
		cout << "公告失败" << endl;
		puts("\n");
	}


	cout << "#更新" << endl;
	js::Update upd;
	if (js::update(upd))
	{
		cout << "ver: " << upd.ver << endl;
		cout << "force: " << upd.force << endl;
		cout << "title: " << upd.title << endl;
		cout << "content: " << upd.content << endl;
		puts("\n");
	}
	else
	{
		cout << "更新失败" << endl;
		puts("\n");
	}

	cout << "#查询" << endl;
	js::Query q;
	if (js::query(key, q))
	{
		cout << "disable: " << q.disable << endl;
		cout << "online: " << q.online << endl;
		cout << "activate: " << q.activate << endl;
		cout << "expired: " << q.expired << endl;
		cout << "unbind_count: " << q.unbind_count << endl;
		puts("\n");
	}
	else
	{
		cout << "查询失败" << endl;
		puts("\n");
	}


	cout << "#登录" << endl;
	HANDLE thread;
	atomic<time_t>* clock;
	if (js::login(key, thread, clock))
	{
		cout << "登录成功" << endl;
		puts("\n");
	}
	else
	{
		cout << "登录失败" << endl;
		puts("\n");
	}


	cout << "#变量" << endl;
	js::Vars vars;
	if (js::var(vars))
	{
		for (const auto& i : vars)
		{
			cout << "name: " << i.name << endl;
			cout << "type: " << i.type << endl;
			if (i.type == js::Var::_i) cout << i.i;
			else if (i.type == js::Var::_d) cout << i.d;
			else if (i.type == js::Var::_s) cout << i.s;
			puts("\n");
		}
	}
	else
	{
		cout << "变量失败" << endl;
		puts("\n");
	}


	Sleep(100000000);

	cout << "#解绑" << endl;
	if (js::unbind(key))
	{
		cout << "解绑成功" << endl;
		puts("\n");
	}
	else
	{
		cout << "解绑失败" << endl;
		puts("\n");
	}

	Sleep(100000000);
}
#endif