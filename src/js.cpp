#include "js.h"
#include "protect.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <cmath>
#include <limits>
#include <openssl/crypto.h>

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonValue>
#include <QString>
#include <QTime>

#include "http.h"
#include "crypto.h"
#include "sha256.h"

constexpr int HEART_RATE_SECONDS = 60;
// Failed heartbeats revoke authorization immediately; no offline retry window.

namespace verify
{
	std::string host;
	inline const std::string domains[] = {
		"api.jsjst.top",
		"api.jsyz.asia",
		"api.jszun.com",
		"cdn.jsjst.top",
		"cdn.jsyz.asia",
		"cdn.jszun.com" };

	void check_host()
	{
		if (!host.empty()) return;
		const int domain_count = sizeof(domains) / sizeof(domains[0]);
		for (int i = 0; i < domain_count; i++)
		{
			const int statusCode = checkDhv2Endpoint(domains[i]);
			if (statusCode == 200)
			{
				host = domains[i];
				return;
			}
			std::cerr << "DHV2域名不可用: " << domains[i] << "，HTTP状态=" << statusCode << std::endl;
		}
		throw std::runtime_error("所有DHV2服务域名均不可用");
	}

	long long nowMillis()
	{
		return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	}

	std::string jsonString(const QJsonObject& object, const QString& name)
	{
		if (!object.contains(name) || !object[name].isString()) throw std::runtime_error("响应缺少字段: " + name.toStdString());
		return object[name].toString().toStdString();
	}
	QString jsonQString(const QJsonObject& object, const QString& name)
	{
		if (!object.contains(name) || !object[name].isString()) throw std::runtime_error("响应缺少字段: " + name.toStdString());
		return object[name].toString();
	}
	std::string optionalJsonString(const QJsonObject& object, const QString& name)
	{
		return object.contains(name) && object[name].isString() ? object[name].toString().toStdString() : std::string();
	}
	QString optionalJsonQString(const QJsonObject& object, const QString& name)
	{
		return object.contains(name) && object[name].isString() ? object[name].toString() : QString();
	}

	int jsonInt(const QJsonObject& object, const QString& name)
	{
		if (!object.contains(name) || !object[name].isDouble()) throw std::runtime_error("响应缺少字段: " + name.toStdString());
        const double value = object[name].toDouble();
        if (!std::isfinite(value) || std::trunc(value) != value || value < std::numeric_limits<int>::min() || value > std::numeric_limits<int>::max()) throw std::runtime_error("响应整数字段无效: " + name.toStdString());
        return static_cast<int>(value);
	}
	int optionalJsonInt(const QJsonObject& object, const QString& name)
	{
		return object.contains(name) && object[name].isDouble() ? object[name].toInt() : 0;
	}

	double jsonDouble(const QJsonObject& object, const QString& name)
	{
		if (!object.contains(name) || !object[name].isDouble()) throw std::runtime_error("响应缺少字段: " + name.toStdString());
		return object[name].toDouble();
	}
	double optionalJsonDouble(const QJsonObject& object, const QString& name)
	{
		return object.contains(name) && object[name].isDouble() ? object[name].toDouble() : 0.0;
	}

	std::string printJson(const QJsonObject& object)
	{
		return QJsonDocument(object).toJson(QJsonDocument::Compact).toStdString();
	}

	time_t toTime(const std::string& time)
	{
		auto t = QDateTime::fromString(QString::fromStdString(time), "yyyy-MM-dd HH:mm:ss");
		if (t.isValid()) return t.toSecsSinceEpoch();
		return 0;
	}
	time_t toTime(const QString& time)
	{
		auto t = QDateTime::fromString(time, "yyyy-MM-dd HH:mm:ss");
		if (t.isValid()) return t.toSecsSinceEpoch();
		return 0;
	}

	class Client
	{
	public:
		void createSession(const std::string& deviceFingerprint)
		{
			VERIFY_VM_BEGIN;
            clearSession();
			crypto::Bytes clientPrivate = crypto::randomBytes(32);
			crypto::Bytes clientPublic = crypto::x25519Public(clientPrivate);
			const std::string clientPublicHex = crypto::toHex(clientPublic);
			crypto::Bytes initShared = crypto::x25519(clientPrivate, crypto::fromHex(js::SERVER_X25519_PUBLIC_KEY));
			crypto::Bytes initKey = crypto::hkdf(initShared, "", crypto::INIT_INFO);

			QJsonObject inner;
			inner["api_key"] = QString::fromStdString(js::API_KEY);
			inner["timestamp"] = static_cast<qint64>(nowMillis());
			inner["nonce"] = QString::fromStdString(crypto::toHex(crypto::randomBytes(16)));
			inner["device_fingerprint"] = QString::fromStdString(deviceFingerprint);
			std::string encryptedInner = crypto::encryptText(printJson(inner), initKey);

			QJsonObject request;
			request["app_id"] = js::APP_ID;
			request["ephemeral_public_key"] = QString::fromStdString(clientPublicHex);
			request["encrypted_data"] = QString::fromStdString(encryptedInner);
			std::string requestBody = printJson(request);

			Dhv2HttpResponse http = dhv2Post(host, "/api/dhv2/session", requestBody, {});
			if (http.status != 200) throw std::runtime_error("建立DHV2会话失败，HTTP状态=" + std::to_string(http.status));

			QJsonObject envelope = parseEnvelope(http.body);
			std::string encryptedResponse = envelopeEncryptedData(envelope);
			std::string responseText = crypto::decryptText(encryptedResponse, initKey);

			QJsonDocument doc = QJsonDocument::fromJson(QByteArray::fromStdString(responseText));
			if (!doc.isObject()) throw std::runtime_error("DHV2会话响应解析失败");
			QJsonObject response = doc.object();

			std::string serverEphemeral = jsonString(response, "server_ephemeral_public");
			std::string ephemeralSignature = jsonString(response, "ephemeral_signature");
			if (!crypto::verifyEd25519(serverEphemeral + clientPublicHex, ephemeralSignature, js::SERVER_ED25519_PUBLIC_KEY))
			{
				throw std::runtime_error("服务端临时公钥签名校验失败");
			}

			crypto::Bytes sessionShared = crypto::x25519(clientPrivate, crypto::fromHex(serverEphemeral));
			crypto::Bytes sessionKey = crypto::hkdf(sessionShared, "", crypto::SESSION_INFO);
			auto transportKey = crypto::hkdf(sessionKey, crypto::TRANSPORT_SALT, crypto::TRANSPORT_INFO);
			auto sessionId = jsonString(response, "session_id");
            if (sessionId.empty()) throw std::runtime_error("DHV2会话ID为空");
			std::string sessionInfoText = crypto::decryptText(jsonString(response, "encrypted_session"), transportKey);

			QJsonDocument sessionDoc = QJsonDocument::fromJson(QByteArray::fromStdString(sessionInfoText));
			if (!sessionDoc.isObject())
			{
				clearSession();
				throw std::runtime_error("DHV2会话信息解析失败");
			}
			QJsonObject sessionInfo = sessionDoc.object();

			if (jsonString(sessionInfo, "session_id") != sessionId || jsonInt(sessionInfo, "app_id") != js::APP_ID)
			{
				clearSession();
				throw std::runtime_error("DHV2会话信息校验失败");
			}
            sessionId_ = std::move(sessionId);
            transportKey_ = std::move(transportKey);
			VERIFY_VM_END;
		}

        // One fresh, authenticated key exchange per business response. This binds
        // responses to one request without requiring undocumented server fields.
        // Never automatically retry login/unbind after an ambiguous network error.
        QJsonObject post(const std::string& apiPath, QJsonObject businessParams, const std::string& deviceFingerprint)
        {
            try
            {
				VERIFY_VM_BEGIN;
                createSession(deviceFingerprint);
                businessParams["timestamp"] = static_cast<qint64>(nowMillis());
                const auto encryptedData = crypto::encryptText(printJson(businessParams), transportKey_);
                std::map<std::string, std::string> headers = {
                    {"X-Crypto-Version", "2"}, {"X-Session-Id", sessionId_},
                    {"X-Encrypted-Api-Key", crypto::encryptText(js::API_KEY, transportKey_)},
                    {"X-Encrypted-Data", encryptedData}
                };
                QJsonObject route;
                route["appId"] = js::APP_ID;
                const auto http = dhv2Post(host, apiPath, printJson(route), headers);
                if (http.status != 200) throw std::runtime_error("DHV2业务接口HTTP状态=" + std::to_string(http.status));
                const auto envelope = parseEnvelope(http.body);
                const auto plaintext = crypto::decryptText(envelopeEncryptedData(envelope), transportKey_);
                const auto doc = QJsonDocument::fromJson(QByteArray::fromStdString(plaintext));
                if (!doc.isObject()) throw std::runtime_error("DHV2业务响应解析失败");
                clearSession();
				VERIFY_VM_END;
                return doc.object();
            }
            catch (...)
            {
                clearSession();
                throw;
            }
        }
        ~Client() { clearSession(); }

	private:
		std::string sessionId_;
		crypto::Bytes transportKey_;

		void clearSession()
		{
			sessionId_.clear();
			if (!transportKey_.empty()) OPENSSL_cleanse(transportKey_.data(), transportKey_.size());
			transportKey_.clear();
		}

		QJsonObject parseEnvelope(const std::string& text)
		{
			VERIFY_VM_BEGIN;
			QJsonDocument doc = QJsonDocument::fromJson(QByteArray::fromStdString(text));
			if (!doc.isObject()) throw std::runtime_error("DHV2外层响应解析失败");
			QJsonObject envelope = doc.object();

			if (jsonInt(envelope, "code") != 0) throw std::runtime_error("DHV2协议层返回失败");

			QJsonObject data = envelope["data"].toObject();
			std::string encrypted = jsonString(data, "encrypted_data");
			std::string signature = jsonString(envelope, "signature");
			std::string canonical = "{\"code\":0,\"data\":{\"encrypted_data\":\"" + encrypted + "\"}}";

			if (!crypto::verifyEd25519(canonical, signature, js::SERVER_ED25519_PUBLIC_KEY)) throw std::runtime_error("DHV2响应签名校验失败");
			VERIFY_VM_END;
			return envelope;
		}

		std::string envelopeEncryptedData(const QJsonObject& envelope)
		{
			return jsonString(envelope["data"].toObject(), "encrypted_data");
		}
	};

	__declspec(noinline) bool append_reg(std::string& buffer, HKEY root, const char* subkey, const char* name, const char* label)
	{
		char tmp[512] = { 0 };
		HKEY hk;
		LONG ret = RegOpenKeyExA(root, subkey, 0, KEY_READ, &hk);
		if (ret != ERROR_SUCCESS) return false;

		DWORD type = 0;
		DWORD size = sizeof(tmp);
		ret = RegQueryValueExA(hk, name, nullptr, &type, reinterpret_cast<LPBYTE>(tmp), &size);
		RegCloseKey(hk);

		if (ret != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) return false;
		tmp[sizeof(tmp) - 1] = '\0';
		if (tmp[0] == '\0') return false;

		buffer.append("|").append(label).append(":").append(tmp);

		return true;
	};
	__declspec(noinline) int get_disk_signature(char* out, size_t out_size)
	{
		VERIFY_VM_BEGIN;
		HANDLE hDisk;
		DWORD bytesReturned = 0;
		BOOL result;

		hDisk = CreateFileA("\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		if (hDisk == INVALID_HANDLE_VALUE)
		{
			out[0] = '\0';
			return -1;
		}

		unsigned char layout_buf[4096];
		{
			unsigned char* _p_dev_64 = (unsigned char*)(layout_buf);
			size_t _n_dev_64 = (sizeof(layout_buf));
			int _c_dev_64 = (0);
			while (_n_dev_64--) *_p_dev_64++ = (unsigned char)_c_dev_64;
		}

		result = DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, NULL, 0, layout_buf, sizeof(layout_buf), &bytesReturned, NULL);
		CloseHandle(hDisk);

		if (result && bytesReturned >= 8)
		{
			DWORD style = *(DWORD*)layout_buf;
			if (style == 0)
			{
				DWORD sig = *(DWORD*)(layout_buf + 8);
				snprintf(out, out_size, "MBR:%08lX", sig);
			}
			else if (style == 1)
			{
				unsigned char* guid = layout_buf + 8;
				snprintf(out, out_size, "GPT:%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
					guid[3], guid[2], guid[1], guid[0], guid[5], guid[4], guid[7],
					guid[6], guid[8], guid[9], guid[10], guid[11], guid[12],
					guid[13], guid[14], guid[15]);
			}
			else
			{
				out[0] = '\0';
				return -1;
			}
			return 0;
		}

		out[0] = '\0';

		VERIFY_VM_END;
		return -1;
	}
	__declspec(noinline) std::string get_device_fingerprint()
	{
		std::string buffer;
		bool fp_ok = false;
		try
		{
			VERIFY_VM_BEGIN;

			// MachineGuid
			append_reg(buffer, HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", "MachineGuid", "MG");

			// 系统盘卷序列号
			{
				DWORD serial = 0;
				char sys_dir[MAX_PATH];
				char root_path[4] = "C:\\";
				if (GetSystemDirectoryA(sys_dir, sizeof(sys_dir)) > 0) root_path[0] = sys_dir[0];
				if (GetVolumeInformationA(root_path, nullptr, 0, &serial, nullptr, nullptr, nullptr, 0) && serial != 0)
				{
					char tmpbuf[20];
					snprintf(tmpbuf, sizeof(tmpbuf), "|VS:%08lX", serial);
					buffer.append(tmpbuf);
				}
			}

			// BIOS/主板信息
			append_reg(buffer, HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemProductName", "SPN");
			append_reg(buffer, HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", "BaseBoardProduct", "BBP");
			append_reg(buffer, HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemManufacturer", "SM");

			// CPU型号
			append_reg(buffer, HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", "ProcessorNameString", "CPU");
			append_reg(buffer, HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", "Identifier", "CPUID");

			// 计算机名
			{
				char comp_name[MAX_COMPUTERNAME_LENGTH + 1];
				DWORD comp_size = sizeof(comp_name);
				if (GetComputerNameA(comp_name, &comp_size)) buffer.append("|CN:").append(comp_name);
			}

			// Windows ProductId
			append_reg(buffer, HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductId", "PID");

			// 磁盘签名
			{
				char disk_sig[128];
				if (get_disk_signature(disk_sig, sizeof(disk_sig)) == 0 && disk_sig[0] != '\0') buffer.append("|DS:").append(disk_sig);
			}

			fp_ok = true;

			VERIFY_VM_END;
		}
		catch (const std::bad_alloc&)
		{
			fp_ok = false;
		}

		if (fp_ok) return Sha256::en_hex(buffer.data(), buffer.size());
		return std::string(64, 'X');
	}

	void requireBusinessSuccess(const QJsonObject& response, const std::string& action, int* code = nullptr)
	{
		VERIFY_VM_BEGIN;
		const int c = jsonInt(response, "code");
		if (code) *code = c;
		if (c != js::BUSINESS_SUCCESS_CODE)
		{
			QJsonValue msg = response["msg"];
			std::string detail = msg.isString() ? msg.toString().toStdString() : "未知错误";
			throw std::runtime_error(action + "失败: " + detail);
		}
		VERIFY_VM_END;
	}
}

namespace js
{
	verify::Client client;
	const std::string device = verify::get_device_fingerprint();
    std::string token;
    std::mutex apiMutex;
    constexpr long long AUTH_LEASE_MILLISECONDS = 150000;
    long long steadyMillis()
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    }
    struct Authorization
    {
        std::atomic<bool> cancelled{true};
        std::atomic<long long> lastSuccess{0};
        // Compatibility output only. Authorization uses lastSuccess, never this clock.
        std::atomic<time_t> clock{0};
        std::thread worker;
        HANDLE handle = nullptr; // owned by this object; callers only borrow it
        std::mutex waitMutex;
        std::condition_variable wake;
        void stop()
        {
            { std::lock_guard lock(waitMutex); cancelled.store(true); }
            lastSuccess.store(0);
            wake.notify_all();
            if (worker.joinable()) worker.join();
            if (handle) { CloseHandle(handle); handle = nullptr; }
            clock.store(0);
        }
        ~Authorization() { stop(); }
    } auth;

    extern "C" bool session_valid()
    {
        // Serialize handle replacement against callers on UI/input threads.
        std::lock_guard lock(apiMutex);
        if (auth.cancelled.load() || !auth.handle || WaitForSingleObject(auth.handle, 0) != WAIT_TIMEOUT) return false;
        const auto last = auth.lastSuccess.load();
        const auto now = steadyMillis();
        return last > 0 && now >= last && now - last < AUTH_LEASE_MILLISECONDS;
    }

	std::string toString(const std::wstring& val, UINT codePage = CP_UTF8)
	{
		int length = WideCharToMultiByte(codePage, 0, val.c_str(), val.size(), 0, 0, 0, 0);
		if (length)
		{
			std::string result(length, 0);
			length = WideCharToMultiByte(codePage, 0, val.c_str(), val.size(), &result[0], length, 0, 0);
			if (length) return result;
		}
		return {};
	}
	std::wstring toWString(const std::string& val, DWORD codePage = CP_UTF8)
	{
		int length = MultiByteToWideChar(codePage, 0, val.c_str(), val.size(), 0, 0);
		if (length)
		{
			std::wstring result(length, 0);
			length = MultiByteToWideChar(codePage, 0, val.c_str(), val.size(), &result[0], length);
			if (length) return result;
		}
		return {};
	}

	void ShowError(const std::string& err)
	{
		MessageBoxW(nullptr, toWString(err).c_str(), L"错误", NULL);
	}

	extern "C" bool notice(Notices& notices)
	{
        std::lock_guard lock(apiMutex);
		using namespace verify;
		if (NOTICE_ID)
		{
			try
			{
				VERIFY_VM_BEGIN;

				check_host();

				QJsonObject params;
				params["variableId"] = QString::fromUtf8(NOTICE_ID);
				QJsonObject response = client.post("/api/expand/variable", params, device);

				requireBusinessSuccess(response, "公告");
				QJsonObject data = response["data"].toObject();
				QString content = jsonQString(data, "content");

				QJsonArray notice = QJsonDocument::fromJson(content.toUtf8()).array();
				if (!notice.isEmpty())
				{
					for (const auto& i : notice)
					{
						const QJsonObject j = i.toObject();
						Notice x;
						x.type = j.value("t").toString().toStdString();
						x.title = j.value("p").toString().toStdString();
						x.content = j.value("c").toString().toStdString();
						notices.push_back(std::move(x));
					}
				}

				VERIFY_VM_END;
				return true;
			}
			catch (const std::exception& e)
			{
				ShowError(e.what());
			}
		}
		return false;
	}
	extern "C" bool update(Update& update)
	{
        std::lock_guard lock(apiMutex);
		using namespace verify;
		if (APP_VERSION <= 0) return true;
		try
		{
			VERIFY_VM_BEGIN;

			check_host();

			QJsonObject params;
			QJsonObject response = client.post("/api/expand/new-ver", params, device);

			requireBusinessSuccess(response, "更新");
			QJsonObject data = response["data"].toObject();
			update.ver = jsonQString(data, "num").toInt();
			update.force = jsonInt(data, "forced");
			update.title = jsonString(data, "name");
			update.content = jsonString(data, "content");

			VERIFY_VM_END;
			return true;
		}
		catch (const std::exception& e)
		{
			ShowError(e.what());
		}
		return false;
	}
	extern "C" bool query(const std::string& card, Query& query)
	{
        std::lock_guard lock(apiMutex);
		using namespace verify;
		try
		{
			VERIFY_VM_BEGIN;

			check_host();

			QJsonObject que;
			que["card"] = QString::fromStdString(card);
			QJsonObject response = client.post("/api/single/info", que, device);

			requireBusinessSuccess(response, "查询");
			QJsonObject data = response["data"].toObject();

			query.disable = jsonInt(data, "isDisable");
			query.online = jsonInt(data, "online");
			query.unbind_count = jsonInt(data, "macCount");

			const QString activates = optionalJsonQString(data, "fromTime");
			if (!activates.isEmpty())
			{
				const time_t activate = toTime(activates);
				if (activate) query.activate = activate;
			}
			const QString expireds = optionalJsonQString(data, "endTime");
			if (!expireds.isEmpty())
			{
				const time_t expired = toTime(expireds);
				if (expired) query.expired = expired;
			}

			VERIFY_VM_END;
			return true;
		}
		catch (const std::exception& e)
		{
			ShowError(e.what());
		}
		return false;
	}
    extern "C" bool login(const std::string& card, HANDLE& thread, std::atomic<time_t>*& heart_clock)
    {
        using namespace verify;
        std::lock_guard lock(apiMutex);
        thread = nullptr;
        heart_clock = nullptr;
        auth.stop();
        if (!token.empty()) OPENSSL_cleanse(token.data(), token.size());
        token.clear();
        try
        {
            VERIFY_VM_BEGIN;
            if (card.empty()) throw std::runtime_error("卡号为空");
            check_host();
            QJsonObject params{{"card", QString::fromStdString(card)}, {"mac", QString::fromStdString(device)}};
            const auto response = client.post("/api/single/login", params, device);
            requireBusinessSuccess(response, "登录");
            const auto newToken = jsonString(response["data"].toObject(), "token");
            if (newToken.empty()) throw std::runtime_error("登录令牌为空");
            // A login Boolean alone cannot publish authenticated UI state.
            Client heartbeatClient;
            QJsonObject heart{{"token", QString::fromStdString(newToken)}};
            requireBusinessSuccess(heartbeatClient.post("/api/single/heart", heart, device), "首次心跳验证");
            token = newToken;
            auth.lastSuccess.store(steadyMillis());
            auth.clock.store(time(nullptr));
            auth.cancelled.store(false);
            auth.worker = std::thread([sessionToken = newToken]() {
                try
                {
                    VERIFY_CHECK;
                    Client heartbeatClient;
                    std::unique_lock waitLock(auth.waitMutex);
                    while (!auth.wake.wait_for(waitLock, std::chrono::seconds(HEART_RATE_SECONDS),
                                              [] { return auth.cancelled.load(); }))
                    {
                        waitLock.unlock();
                        QJsonObject params{{"token", QString::fromStdString(sessionToken)}};
                        requireBusinessSuccess(heartbeatClient.post("/api/single/heart", params, device), "心跳验证");
                        if (auth.cancelled.load()) return;
                        auth.lastSuccess.store(steadyMillis());
                        auth.clock.store(time(nullptr));
                        waitLock.lock();
                    }
                }
                catch (...)
                {
                    auth.lastSuccess.store(0);
                    auth.cancelled.store(true);
                }
            });
            if (!DuplicateHandle(GetCurrentProcess(), auth.worker.native_handle(),
                                 GetCurrentProcess(), &auth.handle, SYNCHRONIZE, FALSE, 0))
                throw std::runtime_error("心跳线程句柄创建失败");
            if (auth.cancelled.load() || WaitForSingleObject(auth.handle, 0) != WAIT_TIMEOUT)
                throw std::runtime_error("心跳线程未运行");
            thread = auth.handle;
            heart_clock = &auth.clock;
            VERIFY_VM_END;
            return true;
        }
        catch (const std::exception& e)
        {
            auth.stop();
            if (!token.empty()) OPENSSL_cleanse(token.data(), token.size());
            token.clear();
            ShowError(e.what());
        }
        return false;
    }

	extern "C" bool var(Vars& vars)
	{
        if (!session_valid()) return false;
        std::lock_guard lock(apiMutex);
		using namespace verify;
		if (VAR_ID && !token.empty() && !auth.cancelled.load())
		{
			try
			{
				VERIFY_VM_BEGIN;

				check_host();

				QJsonObject params;
				params["variableId"] = QString::fromUtf8(VAR_ID);
				params["token"] = QString::fromStdString(token);
				QJsonObject response = client.post("/api/expand/variable", params, device);

				requireBusinessSuccess(response, "公告");
				QJsonObject data = response["data"].toObject();
				QString content = jsonQString(data, "content");

				QJsonArray var = QJsonDocument::fromJson(content.toUtf8()).array();
				if (!var.isEmpty())
				{
					for (const auto& i : var)
					{
						const QJsonObject j = i.toObject();
						Var x;
						const QString type = j.value("t").toString();
						if (type == "i") x.type = Var::_i, x.i = optionalJsonInt(j, "v");
						else if (type == "d") x.type = Var::_d, x.d = optionalJsonDouble(j, "v");
						else x.type = Var::_s, x.s = optionalJsonString(j, "v");
						x.name = j.value("n").toString().toStdString();
						vars.push_back(std::move(x));
					}
				}

				VERIFY_VM_END;
				return true;
			}
			catch (const std::exception& e)
			{
				ShowError(e.what());
			}
		}
		return false;
	}
	extern "C" bool unbind(const std::string& card)
	{
        std::lock_guard lock(apiMutex);
		using namespace verify;
		try
		{
			VERIFY_VM_BEGIN;

			check_host();

			QJsonObject que;
			que["card"] = QString::fromStdString(card);
			que["originalMac"] = QString::fromStdString(device);
			QJsonObject response = client.post("/api/single/unbind", que, device);

			requireBusinessSuccess(response, "解绑");

			VERIFY_VM_END;
			return true;
		}
		catch (const std::exception& e)
		{
			ShowError(e.what());
		}
		return false;
	}
}