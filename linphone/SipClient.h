/**
 * SipClient.h
 */
#ifndef __SIP_CLIENT_H__
#define __SIP_CLIENT_H__
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <mutex>
#include "coreapi/linphonecore.h"
#include "SignalingEvents.h"

namespace mrtc {

#ifdef SIP_TEST
	typedef struct RegisterInfo
	{
		RegisterInfo(std::string proxy,
								std::string display,
								std::string username,
								std::string authname,
								std::string authpwd,
								std::string realm) 
		: proxy(proxy)
		, display(display)
		, username(username)
		, authname(authname)
		, authpwd(authpwd)
		, realm(realm){			
		}

		RegisterInfo(std::string proxy,
			std::string display,
			std::string username,
			std::string authname,
			std::string authpwd)
			: proxy(proxy)
			, display(display)
			, username(username)
			, authname(authname)
			, authpwd(authpwd) {
		}

		bool operator == (const RegisterInfo &info) {
			return ((!proxy.compare(info.proxy)) &&
						  (!display.compare(info.display)) &&
							(!username.compare(info.username)) &&
							(!authname.compare(info.authname)) &&
							(!authpwd.compare(info.authpwd)) &&
							(!realm.compare(info.realm)));
		}

		std::string proxy;
		std::string display;
		std::string username;
		std::string authname;
		std::string authpwd;
		std::string realm;
	} RegisterInfo;
#endif

class SipClient
{
public:
	explicit SipClient(SignalingEvents *events);
	~SipClient();

	/**
	 * Initialize client
	 */
	int32_t initialize();

	/**
	 * Initialize Linphone core callback table
	 */
	void initVtable();

	/**
	 * Build and send Initialize REGISTER message.
	 * @param proxy			register proxy
	 * @param display		sip url display name
	 * @param username	sip url username
	 * @param authname	Register authentication name
	 * @param authpwd		Register authentication password
	 * @param realm			Register authentication realm
	 */
	int32_t doRegister(const std::string &proxy, const std::string &display,
										const std::string &username, const std::string &authname,
										const std::string &authpwd, const std::string &realm = "");

	/**
	 * Send REGISTER Message with expire = 0
	 */
	int32_t doUnRegister();

	/**
	 * Build and send Initialize INVITE message
	 * @param callee The peer number or identity would fill to INVITE To Header
	 * @param offer Callers' SDP
	 */
	int32_t doInitInvite(const std::string &callee, const std::string &offer);

	/**
	 * Build and send 200OK to accept the call
	 * @param answer Callees' SDP
	 */
	int32_t doAcceptCall(const std::string &answer);

	/**
	 * Build and send BYE to terminate the connected call,
	 * or Send CANCEL to abort the outgoing call,
	 * or Send 603 to reject the incoming call
	 */
	int32_t doHangup();
	
	/* LinphoneCoreVTable callbacks */
	static void globalStateCb(LinphoneCore *lc, LinphoneGlobalState gstate, const char *message);
	static void callStateCb(LinphoneCore *lc, LinphoneCall *call, LinphoneCallState cstate, const char *message);
	static void registrationStateCb(LinphoneCore *lc, LinphoneProxyConfig *cfg, LinphoneRegistrationState cstate, const char *message);
	static void displayStatusCb(LinphoneCore *lc, const char *message);
	static void callLogUpdated(LinphoneCore *lc, LinphoneCallLog *newcl);
	static void displayMessage(LinphoneCore *lc, const char *message);
	static void displayWarning(LinphoneCore *lc, const char *message);
	
private:
	

protected:
	void SipIterate();

private:
	LinphoneCore * _ptrLc;
	LinphoneCoreVTable _vtable;
	SignalingEvents *_events;

	bool _running{ false };
	std::unique_ptr<std::thread> _iterate_thread;
	const char* _thread_name;	

	LinphoneCall *_current_call;
};
} /* namespace mrtc */
#endif /* __SIP_CLIENT_H__ */