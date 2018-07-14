#include "SipClient.h"
#include <iostream>
#include <thread>
#include <chrono>

using namespace std;
namespace mrtc {

#define INITIALIZED_CHECK_VALUE(value) \
	if (linphone_core_get_global_state(_ptrLc) != LinphoneGlobalOn) \
	{ \
		return value;\
	}

#define INITIALIZED_CHECK() \
	if (linphone_core_get_global_state(_ptrLc) != LinphoneGlobalOn) \
	{ \
		return;\
	}
	
SipClient::SipClient(SignalingEvents * events)
	: _ptrLc(nullptr)
	, _events(events)
	, _thread_name("LcIterateThread")
	, _running(false)
	, _current_call(nullptr)
{
	initialize();
}
	
SipClient::~SipClient()
{
	if (_running)
	{
		_running = false;
		_iterate_thread->join();
		_iterate_thread.reset();
	}
	
	if (_ptrLc)
	{
		linphone_core_destroy(_ptrLc);
		_ptrLc = nullptr;
	}	
}

int32_t SipClient::initialize()
{
	initVtable();
	_ptrLc = linphone_core_new_with_config(&_vtable, this);
	
	_running = true;
	_iterate_thread.reset(new std::thread(&SipClient::SipIterate, this));
	
	return 0;
}

void SipClient::initVtable()
{
	_vtable.global_state_changed = globalStateCb;
	_vtable.registration_state_changed = registrationStateCb;
	_vtable.call_state_changed = callStateCb;
	_vtable.auth_info_requested = nullptr;
	_vtable.call_log_updated = callLogUpdated;
	_vtable.dtmf_received = nullptr;
	_vtable.refer_received = nullptr;
	_vtable.call_encryption_changed = nullptr;
	_vtable.transfer_state_changed = nullptr;
	_vtable.notify_recv = nullptr;
	_vtable.display_status = displayStatusCb;
	_vtable.display_message = displayMessage;
	_vtable.display_warning = displayWarning;
	_vtable.display_url = nullptr;
	_vtable.show = nullptr;
}

int32_t SipClient::doRegister(const std::string &proxy, const std::string &display,
														const std::string &username, const std::string &authname,
														const std::string &authpwd, const std::string &realm)
{
	INITIALIZED_CHECK_VALUE(-1);

	char identity[256] = { 0 };

	if (proxy.empty() || username.empty() || authname.empty()	|| authpwd.empty())
	{
		return -1;
	}

	if (!display.empty())
	{
		snprintf(identity, sizeof(identity), "\"%s\"<sip:%s@%s>", 
					display.c_str(), username.c_str(), proxy.c_str());
	}
	else
	{
		snprintf(identity, sizeof(identity), "sip:%s@%s", username.c_str(), proxy.c_str());
	}

	LinphoneProxyConfig *proxy_cfg = nullptr;
	LinphoneAuthInfo *auth_info = nullptr;

	auth_info = linphone_auth_info_new(authname.c_str(), username.c_str(), authpwd.c_str(), NULL, realm.c_str());
	linphone_core_add_auth_info(_ptrLc, auth_info);
	linphone_auth_info_destroy(auth_info);

	proxy_cfg = linphone_proxy_config_new();
	linphone_proxy_config_set_identity(proxy_cfg, identity);
	linphone_proxy_config_set_server_addr(proxy_cfg, proxy.c_str());
	linphone_proxy_config_set_expires(proxy_cfg, 120);
	linphone_proxy_config_enable_register(proxy_cfg, TRUE);
	linphone_core_add_proxy_config(_ptrLc, proxy_cfg);
	linphone_core_set_default_proxy(_ptrLc, proxy_cfg);


	return 0;
}

int32_t SipClient::doUnRegister()
{
	INITIALIZED_CHECK_VALUE(-1);

	LinphoneProxyConfig *proxy_cfg = nullptr;

	linphone_core_get_default_proxy(_ptrLc, &proxy_cfg); /* get default proxy config*/
	linphone_proxy_config_edit(proxy_cfg); /*start editing proxy configuration*/
	linphone_proxy_config_enable_register(proxy_cfg, FALSE); /*de-activate registration for this proxy config*/
  return linphone_proxy_config_done(proxy_cfg); /*initiate REGISTER with expire = 0*/
}

int32_t SipClient::doInitInvite(const std::string &callee, const std::string &offer)
{
	INITIALIZED_CHECK_VALUE(-1);

	if (callee.empty() || offer.empty())
	{
		return -1;
	}

	if (linphone_core_invite_sdp(_ptrLc, callee.c_str(), offer.c_str()) == nullptr)
	{
		return -1;
	}

	return 0;
}

int32_t SipClient::doAcceptCall(const std::string &answer)
{
	INITIALIZED_CHECK_VALUE(-1);
	if (answer.empty())
	{
		return -1;
	}

	linphone_call_set_local_sdp_str(_current_call, answer.c_str());
	return linphone_core_accept_call(_ptrLc, _current_call);
}

int32_t SipClient::doHangup()
{
	INITIALIZED_CHECK_VALUE(-1);

	return linphone_core_terminate_all_calls(_ptrLc);
}

void SipClient::globalStateCb(LinphoneCore * lc, LinphoneGlobalState gstate, const char * message)
{
	if (message != nullptr)
	{
		cout << "globalState: " << message << endl;
	}
}

void SipClient::callStateCb(LinphoneCore * lc, LinphoneCall * call, LinphoneCallState cstate, const char * message)
{
	//char *from = linphone_call_get_remote_address_as_string(call);
	const LinphoneAddress *fromaddr = linphone_call_get_remote_address(call);
	const char *from = linphone_address_get_username(fromaddr);

	long id = (long)linphone_call_get_user_pointer(call);
	SipClient *sipclient = static_cast<SipClient*>(linphone_core_get_user_data(lc));

	printf("call state: %s\n", linphone_call_state_to_string(cstate));

	switch (cstate) {
	case LinphoneCallEnd:
		printf("Call %i with %s ended (%s).\n", id, from, linphone_reason_to_string(linphone_call_get_reason(call)));
		break;
	case LinphoneCallResuming:
		printf("Resuming call %i with %s.\n", id, from);
		break;
	case LinphoneCallStreamsRunning:
		printf("Media streams established with %s for call %i (%s).\n", from, id, (linphone_call_params_video_enabled(linphone_call_get_current_params(call)) ? "video" : "audio"));
		break;
	case LinphoneCallPausing:
		printf("Pausing call %i with %s.\n", id, from);
		break;
	case LinphoneCallPaused:
		printf("Call %i with %s is now paused.\n", id, from);
		break;
	case LinphoneCallPausedByRemote:
		printf("Call %i has been paused by %s.\n", id, from);
		break;
	case LinphoneCallIncomingReceived:
	{
		printf("Receiving new incoming call from %s, assigned id %i\n", from, id);
		
		sipclient->_current_call = call;
	}
		break;
	case LinphoneCallOutgoingInit:
		printf("Establishing call id to %s, assigned id %i\n", from, id);
		break;
	case LinphoneCallUpdatedByRemote:		
		printf("Call %i to %s update by remote.\n", id, from);
		linphone_core_defer_call_update(lc, call);
		break;
	case LinphoneCallOutgoingProgress:
	{
		printf("Call %i to %s in progress.\n", id, from);
	}
		break;
	case LinphoneCallOutgoingRinging:
		printf("Call %i to %s ringing.\n", id, from);
		break;
	case LinphoneCallConnected:
		printf("Call %i with %s connected.\n", id, from);
		break;
	case LinphoneCallOutgoingEarlyMedia:
		printf("Call %i with %s early media.\n", id, from);
		break;
	case LinphoneCallError:
		printf("Call %i with %s error.\n", id, from);
		break;
	default:
		break;
	}

	//ms_free(from);
}

void SipClient::registrationStateCb(LinphoneCore * lc, LinphoneProxyConfig * cfg, LinphoneRegistrationState cstate, const char * message)
{
	if (message != nullptr)
	{
		cout << "registrationState: " << message << endl;
	}

	printf("New registration state %s for user id [%s] at proxy [%s]\n"
				, linphone_registration_state_to_string(cstate)
				, linphone_proxy_config_get_identity(cfg)
				, linphone_proxy_config_get_addr(cfg));

	SipClient *client = static_cast<SipClient*>(linphone_core_get_user_data(lc));
	switch (cstate)
	{
	case LinphoneRegistrationOk:
	{
		if (client->_events)
		{
			client->_events->onRegistered(true);
		}
	}
	break;

	case LinphoneRegistrationCleared:
	{
		if (client->_events)
		{
			client->_events->onRegistered(false);
		}
	}
	break;

	case LinphoneRegistrationFailed:
	{
		
	}
		break;
	default:
		break;
	}
}

void SipClient::displayStatusCb(LinphoneCore * lc, const char * message)
{
	if (message != nullptr)
	{
		cout << "status: " << message << endl;
	}
}

void SipClient::callLogUpdated(LinphoneCore * lc, LinphoneCallLog * newcl)
{
	if (newcl != nullptr)
	{
		char * cl = linphone_call_log_to_str(newcl);
		printf("\ncall log: %s\n", cl);
		ms_free(cl);
		cl = nullptr;
	}
}

void SipClient::displayMessage(LinphoneCore * lc, const char * message)
{
	if (message != nullptr)
	{
		cout << "displayMessage: " << message << endl;
	}
}

void SipClient::displayWarning(LinphoneCore * lc, const char * message)
{
	if (message != nullptr)
	{
		cout << "displayWarning: " << message << endl;
	}
}

void SipClient::SipIterate()
{
	while (_running)
	{
		linphone_core_iterate(_ptrLc);

		std::this_thread::sleep_for(std::chrono::milliseconds(50));
	}	
}
} /* namespace msip */