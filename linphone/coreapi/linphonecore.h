/*
linphone
Copyright (C) 2000 - 2010 Simon MORLAT (simon.morlat@linphone.org)

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/
#ifndef LINPHONECORE_H
#define LINPHONECORE_H

#include "payloadtype.h"
#include "mscommon.h"
#include "sal_api.h"

#define LINPHONE_IPADDR_SIZE 64
#define LINPHONE_HOSTNAME_SIZE 128

#ifdef __cplusplus
extern "C" {
#endif
struct _LinphoneCore;
typedef struct _LinphoneVTable LinphoneCoreVTable;

	/**
	* Enum describing remote friend status
	*/
typedef enum _LinphoneOnlineStatus {
	/**
	* Offline
	*/
	LinphoneStatusOffline,
	/**
	* Online
	*/
	LinphoneStatusOnline,
	/**
	* Busy
	*/
	LinphoneStatusBusy,
	/**
	* Be right back
	*/
	LinphoneStatusBeRightBack,
	/**
	* Away
	*/
	LinphoneStatusAway,
	/**
	* On the phone
	*/
	LinphoneStatusOnThePhone,
	/**
	* Out to lunch
	*/
	LinphoneStatusOutToLunch,
	/**
	* Do not disturb
	*/
	LinphoneStatusDoNotDisturb,
	/**
	* Moved in this sate, call can be redirected if an alternate contact address has been set using function linphone_core_set_presence_info()
	*/
	LinphoneStatusMoved,
	/**
	* Using another messaging service
	*/
	LinphoneStatusAltService,
	/**
	* Pending
	*/
	LinphoneStatusPending,

	LinphoneStatusEnd
}LinphoneOnlineStatus;

typedef struct _LinphoneCore LinphoneCore;

/**
 * Linphone core SIP transport ports.
 * Use with #linphone_core_set_sip_transports
 * @ingroup initializing
 */
typedef enum {
	LcTransportUDP, /*UDP*/
	LcTransportTCP, /*TCP*/
	LcTransportTLS, /*TLS*/
	LcTransportDTLS /*DTLS*/
} LCSipTransport;

typedef struct _LCSipTransports{
	/**
	 * transport to listening on
	 */
	LCSipTransport transport;

	/**
	 * udp port to listening on, negative value if not set
	 * */
	int udp_port;
	/**
	 * tcp port to listening on, negative value if not set
	 * */
	int tcp_port;
	/**
	 * dtls port to listening on, negative value if not set
	 * */
	int dtls_port;
	/**
	 * tls port to listening on, negative value if not set
	 * */
	int tls_port;
} LCSipTransports;


/**
 * Object that represents a SIP address.
 *
 * The LinphoneAddress is an opaque object to represents SIP addresses, ie
 * the content of SIP's 'from' and 'to' headers.
 * A SIP address is made of display name, username, domain name, port, and various
 * uri headers (such as tags). It looks like 'Alice <sip:alice@example.net>'.
 * The LinphoneAddress has methods to extract and manipulate all parts of the address.
 * When some part of the address (for example the username) is empty, the accessor methods
 * return NULL.
 *
 * @ingroup linphone_address
 * @var LinphoneAddress
 */
typedef struct SalAddress LinphoneAddress;

LinphoneAddress * linphone_address_new(const char *uri);
LinphoneAddress * linphone_address_clone(const LinphoneAddress *uri);
const char *linphone_address_get_scheme(const LinphoneAddress *u);
const char *linphone_address_get_display_name(const LinphoneAddress* u);
const char *linphone_address_get_username(const LinphoneAddress *u);
const char *linphone_address_get_domain(const LinphoneAddress *u);
/**
 * Get port number as an integer value.
 *
 */
int linphone_address_get_port_int(const LinphoneAddress *u);
/**
 * Get port number, null if not present.
 */
const char* linphone_address_get_port(const LinphoneAddress *u);
void linphone_address_set_display_name(LinphoneAddress *u, const char *display_name);
void linphone_address_set_username(LinphoneAddress *uri, const char *username);
void linphone_address_set_domain(LinphoneAddress *uri, const char *host);
void linphone_address_set_port(LinphoneAddress *uri, const char *port);
void linphone_address_set_port_int(LinphoneAddress *uri, int port);
/*remove tags, params etc... so that it is displayable to the user*/
void linphone_address_clean(LinphoneAddress *uri);
char *linphone_address_as_string(const LinphoneAddress *u);
char *linphone_address_as_string_uri_only(const LinphoneAddress *u);
bool_t linphone_address_weak_equal(const LinphoneAddress *a1, const LinphoneAddress *a2);
void linphone_address_destroy(LinphoneAddress *u);

/**
 * Enum representing the direction of a call.
 * @ingroup call_logs
**/
enum _LinphoneCallDir {
	LinphoneCallOutgoing, /**< outgoing calls*/
	LinphoneCallIncoming  /**< incoming calls*/
};

/**
 * Typedef for enum
 * @ingroup call_logs
**/
typedef enum _LinphoneCallDir LinphoneCallDir;

/**
 * Enum representing the status of a call
 * @ingroup call_logs
**/
typedef enum _LinphoneCallStatus {
	LinphoneCallSuccess, /**< The call was sucessful*/
	LinphoneCallAborted, /**< The call was aborted */
	LinphoneCallMissed, /**< The call was missed (unanswered)*/
	LinphoneCallDeclined /**< The call was declined, either locally or by remote end*/
} LinphoneCallStatus;

/**
 * Structure representing a call log.
 *
 * @ingroup call_logs
 *
**/
typedef struct _LinphoneCallLog LinphoneCallLog;

/**
 * Enum describing type of media encryption types.
**/
typedef enum LinphoneMediaEncryption LinphoneMediaEncryption;

/*public: */
LinphoneAddress *linphone_call_log_get_from(LinphoneCallLog *cl);
LinphoneAddress *linphone_call_log_get_to(LinphoneCallLog *cl);
LinphoneAddress *linphone_call_log_get_remote_address(LinphoneCallLog *cl);
LinphoneCallDir linphone_call_log_get_dir(LinphoneCallLog *cl);
LinphoneCallStatus linphone_call_log_get_status(LinphoneCallLog *cl);
LinphoneCallStatus linphone_call_log_video_enabled(LinphoneCallLog *cl);
time_t linphone_call_log_get_start_date(LinphoneCallLog *cl);
int linphone_call_log_get_duration(LinphoneCallLog *cl);
float linphone_call_log_get_quality(LinphoneCallLog *cl);
void linphone_call_log_set_user_pointer(LinphoneCallLog *cl, void *up);
void *linphone_call_log_get_user_pointer(const LinphoneCallLog *cl);
void linphone_call_log_set_ref_key(LinphoneCallLog *cl, const char *refkey);
const char *linphone_call_log_get_ref_key(const LinphoneCallLog *cl);
const char *linphone_call_log_get_call_id(const LinphoneCallLog *cl);
char * linphone_call_log_to_str(LinphoneCallLog *cl);

struct _LinphoneCallParams;

/**
 * The LinphoneCallParams is an object containing various call related parameters.
 * It can be used to retrieve parameters from a currently running call or modify the call's characteristics
 * dynamically.
**/
typedef struct _LinphoneCallParams LinphoneCallParams;

LinphoneCallParams * linphone_call_params_copy(const LinphoneCallParams *cp);
void linphone_call_params_enable_video(LinphoneCallParams *cp, bool_t enabled);
bool_t linphone_call_params_video_enabled(const LinphoneCallParams *cp);
void linphone_call_params_enable_early_media_sending(LinphoneCallParams *cp, bool_t enabled);
bool_t linphone_call_params_early_media_sending_enabled(const LinphoneCallParams *cp);
bool_t linphone_call_params_local_conference_mode(const LinphoneCallParams *cp);
void linphone_call_params_destroy(LinphoneCallParams *cp);
void linphone_call_params_add_custom_header(LinphoneCallParams *params, const char *header_name, const char *header_value);
const char *linphone_call_params_get_custom_header(const LinphoneCallParams *params, const char *header_name);

/**
 * Enum describing failure reasons.
 * @ingroup initializing
**/
enum _LinphoneReason{
	LinphoneReasonNone,
	LinphoneReasonNoResponse, /**<No response received from remote*/
	LinphoneReasonBadCredentials, /**<Authentication failed due to bad or missing credentials*/
	LinphoneReasonDeclined, /**<The call has been declined*/
	LinphoneReasonNotFound, /**<Destination of the calls was not found.*/
	LinphoneReasonNotAnswered, /**<The call was not answered in time*/
	LinphoneReasonBusy /**<Phone line was busy */
};

/**
 * Enum describing failure reasons.
 * @ingroup initializing
**/
typedef enum _LinphoneReason LinphoneReason;

const char *linphone_reason_to_string(LinphoneReason err);

/**
 * The LinphoneCall object represents a call issued or received by the LinphoneCore
 * @ingroup call_control
**/
struct _LinphoneCall;
/**
 * The LinphoneCall object represents a call issued or received by the LinphoneCore
 * @ingroup call_control
**/
typedef struct _LinphoneCall LinphoneCall;


/**
 * LinphoneCallState enum represents the different state a call can reach into.
 * The application is notified of state changes through the LinphoneCoreVTable::call_state_changed callback.
 * @ingroup call_control
**/
typedef enum _LinphoneCallState{
	LinphoneCallIdle,					/**<Initial call state */
	LinphoneCallIncomingReceived, /**<This is a new incoming call */
	LinphoneCallOutgoingInit, /**<An outgoing call is started */
	LinphoneCallOutgoingProgress, /**<An outgoing call is in progress */
	LinphoneCallOutgoingRinging, /**<An outgoing call is ringing at remote end */
	LinphoneCallOutgoingEarlyMedia, /**<An outgoing call is proposed early media */
	LinphoneCallConnected, /**<Connected, the call is answered */
	LinphoneCallStreamsRunning, /**<The media streams are established and running*/
	LinphoneCallPausing, /**<The call is pausing at the initiative of local end */
	LinphoneCallPaused, /**< The call is paused, remote end has accepted the pause */
	LinphoneCallResuming, /**<The call is being resumed by local end*/
	LinphoneCallRefered, /**<The call is being transfered to another party, resulting in a new outgoing call to follow immediately*/
	LinphoneCallError, /**<The call encountered an error*/
	LinphoneCallEnd, /**<The call ended normally*/
	LinphoneCallPausedByRemote, /**<The call is paused by remote end*/
	LinphoneCallUpdatedByRemote, /**<The call's parameters change is requested by remote end, used for example when video is added by remote */
	LinphoneCallIncomingEarlyMedia, /**<We are proposing early media to an incoming call */
	LinphoneCallUpdating, /**<A call update has been initiated by us */
	LinphoneCallReleased /**< The call object is no more retained by the core */
} LinphoneCallState;

const char *linphone_call_state_to_string(LinphoneCallState cs);

LinphoneCore *linphone_call_get_core(const LinphoneCall *call);
LinphoneCallState linphone_call_get_state(const LinphoneCall *call);
bool_t linphone_call_asked_to_autoanswer(LinphoneCall *call);
const LinphoneAddress * linphone_core_get_current_call_remote_address(struct _LinphoneCore *lc);
const LinphoneAddress * linphone_call_get_remote_address(const LinphoneCall *call);
char *linphone_call_get_remote_address_as_string(const LinphoneCall *call);
char *linphone_call_get_remote_sdp_str(LinphoneCall *call);
void linphone_call_set_local_sdp_str(const LinphoneCall *call, const char* sdp);
LinphoneCallDir linphone_call_get_dir(const LinphoneCall *call);
LinphoneCall * linphone_call_ref(LinphoneCall *call);
void linphone_call_unref(LinphoneCall *call);
LinphoneCallLog *linphone_call_get_call_log(const LinphoneCall *call);
const char *linphone_call_get_refer_to(const LinphoneCall *call);
bool_t linphone_call_has_transfer_pending(const LinphoneCall *call);
LinphoneCall *linphone_call_get_replaced_call(LinphoneCall *call);
int linphone_call_get_duration(const LinphoneCall *call);
const LinphoneCallParams * linphone_call_get_current_params(LinphoneCall *call);
const LinphoneCallParams * linphone_call_get_remote_params(LinphoneCall *call);
LinphoneReason linphone_call_get_reason(const LinphoneCall *call);
const char *linphone_call_get_remote_user_agent(LinphoneCall *call);
const char *linphone_call_get_remote_contact(LinphoneCall *call);
const char* linphone_call_get_authentication_token(LinphoneCall *call);
bool_t linphone_call_get_authentication_token_verified(LinphoneCall *call);
void linphone_call_send_vfu_request(LinphoneCall *call);
void *linphone_call_get_user_pointer(LinphoneCall *call);
void linphone_call_set_user_pointer(LinphoneCall *call, void *user_pointer);
LinphoneCallState linphone_call_get_transfer_state(LinphoneCall *call);

/**
 * Return TRUE if this call is currently part of a conference
 *@param call #LinphoneCall
 *@return TRUE if part of a conference.
 *
 @ingroup call_control
 */
bool_t linphone_call_is_in_conference(const LinphoneCall *call);

/**
 * @addtogroup proxies
 * @{
**/
/**
 * The LinphoneProxyConfig object represents a proxy configuration to be used
 * by the LinphoneCore object.
 * Its fields must not be used directly in favour of the accessors methods.
 * Once created and filled properly the LinphoneProxyConfig can be given to
 * LinphoneCore with linphone_core_add_proxy_config().
 * This will automatically triggers the registration, if enabled.
 *
 * The proxy configuration are persistent to restarts because they are saved
 * in the configuration file. As a consequence, after linphone_core_new() there
 * might already be a list of configured proxy that can be examined with
 * linphone_core_get_proxy_config_list().
 *
 * The default proxy (see linphone_core_set_default_proxy() ) is the one of the list
 * that is used by default for calls.
**/
typedef struct _LinphoneProxyConfig LinphoneProxyConfig;

/**
 * LinphoneRegistrationState describes proxy registration states.
**/
typedef enum _LinphoneRegistrationState{
	LinphoneRegistrationNone, /**<Initial state for registrations */
	LinphoneRegistrationProgress, /**<Registration is in progress */
	LinphoneRegistrationOk,	/**< Registration is successful */
	LinphoneRegistrationCleared, /**< Unregistration succeeded */
	LinphoneRegistrationFailed	/**<Registration failed */
}LinphoneRegistrationState;

/**
 * Human readable version of the #LinphoneRegistrationState
 * @param cs sate
 */
const char *linphone_registration_state_to_string(LinphoneRegistrationState cs);

LinphoneProxyConfig *linphone_proxy_config_new(void);
int linphone_proxy_config_set_server_addr(LinphoneProxyConfig *obj, const char *server_addr);
int linphone_proxy_config_set_identity(LinphoneProxyConfig *obj, const char *identity);
int linphone_proxy_config_set_route(LinphoneProxyConfig *obj, const char *route);
void linphone_proxy_config_set_expires(LinphoneProxyConfig *obj, int expires);
/**
 * Indicates  either or not, REGISTRATION must be issued for this #LinphoneProxyConfig .
 * <br> In case this #LinphoneProxyConfig has been added to #LinphoneCore, follows the linphone_proxy_config_edit() rule.
 * @param obj object pointer
 * @param val if true, registration will be engaged
 */
void linphone_proxy_config_enable_register(LinphoneProxyConfig *obj, bool_t val);
#define linphone_proxy_config_enableregister linphone_proxy_config_enable_register
void linphone_proxy_config_edit(LinphoneProxyConfig *obj);
int linphone_proxy_config_done(LinphoneProxyConfig *obj);

/**
 * Indicates  either or not, PUBLISH must be issued for this #LinphoneProxyConfig .
 * <br> In case this #LinphoneProxyConfig has been added to #LinphoneCore, follows the linphone_proxy_config_edit() rule.
 * @param obj object pointer
 * @param val if true, publish will be engaged
 *
 */
void linphone_proxy_config_enable_publish(LinphoneProxyConfig *obj, bool_t val);
void linphone_proxy_config_set_dial_escape_plus(LinphoneProxyConfig *cfg, bool_t val);
void linphone_proxy_config_set_dial_prefix(LinphoneProxyConfig *cfg, const char *prefix);

LinphoneRegistrationState linphone_proxy_config_get_state(const LinphoneProxyConfig *obj);
bool_t linphone_proxy_config_is_registered(const LinphoneProxyConfig *obj);
const char *linphone_proxy_config_get_domain(const LinphoneProxyConfig *cfg);

const char *linphone_proxy_config_get_route(const LinphoneProxyConfig *obj);
const char *linphone_proxy_config_get_identity(const LinphoneProxyConfig *obj);
bool_t linphone_proxy_config_publish_enabled(const LinphoneProxyConfig *obj);
const char *linphone_proxy_config_get_addr(const LinphoneProxyConfig *obj);
int linphone_proxy_config_get_expires(const LinphoneProxyConfig *obj);
bool_t linphone_proxy_config_register_enabled(const LinphoneProxyConfig *obj);
void linphone_proxy_config_refresh_register(LinphoneProxyConfig *obj);
const char *linphone_proxy_config_get_contact_parameters(const LinphoneProxyConfig *obj);
void linphone_proxy_config_set_contact_parameters(LinphoneProxyConfig *obj, const char *contact_params);
struct _LinphoneCore * linphone_proxy_config_get_core(const LinphoneProxyConfig *obj);

bool_t linphone_proxy_config_get_dial_escape_plus(const LinphoneProxyConfig *cfg);
const char * linphone_proxy_config_get_dial_prefix(const LinphoneProxyConfig *cfg);

LinphoneReason linphone_proxy_config_get_error(const LinphoneProxyConfig *cfg);

/* destruction is called automatically when removing the proxy config */
void linphone_proxy_config_destroy(LinphoneProxyConfig *cfg);

/*
 *  attached a user data to a proxy config
 */
void linphone_proxy_config_set_user_data(LinphoneProxyConfig *cr, void * ud);
/*
 *  get user data to a proxy config. return null if any
 */
void * linphone_proxy_config_get_user_data(LinphoneProxyConfig *cr);

struct _LinphoneAuthInfo;

/**
 * @ingroup authentication
 * Object holding authentication information.
 *
 * @note The object's fields should not be accessed directly. Prefer using
 * the accessor methods.
 *
 * In most case, authentication information consists of a username and password.
 * Sometimes, a userid is required by proxy, and realm can be useful to discriminate
 * different SIP domains.
 *
 * Once created and filled, a LinphoneAuthInfo must be added to the LinphoneCore in
 * order to become known and used automatically when needed.
 * Use linphone_core_add_auth_info() for that purpose.
 *
 * The LinphoneCore object can take the initiative to request authentication information
 * when needed to the application through the auth_info_requested callback of the
 * LinphoneCoreVTable structure.
 *
 * The application can respond to this information request later using
 * linphone_core_add_auth_info(). This will unblock all pending authentication
 * transactions and retry them with authentication headers.
 *
**/
typedef struct _LinphoneAuthInfo LinphoneAuthInfo;

LinphoneAuthInfo *linphone_auth_info_new(const char *username, const char *userid,
		const char *passwd, const char *ha1,const char *realm);
void linphone_auth_info_set_passwd(LinphoneAuthInfo *info, const char *passwd);
void linphone_auth_info_set_username(LinphoneAuthInfo *info, const char *username);
void linphone_auth_info_set_userid(LinphoneAuthInfo *info, const char *userid);
void linphone_auth_info_set_realm(LinphoneAuthInfo *info, const char *realm);
void linphone_auth_info_set_ha1(LinphoneAuthInfo *info, const char *ha1);

const char *linphone_auth_info_get_username(const LinphoneAuthInfo *i);
const char *linphone_auth_info_get_passwd(const LinphoneAuthInfo *i);
const char *linphone_auth_info_get_userid(const LinphoneAuthInfo *i);
const char *linphone_auth_info_get_realm(const LinphoneAuthInfo *i);
const char *linphone_auth_info_get_ha1(const LinphoneAuthInfo *i);

/* you don't need those function*/
void linphone_auth_info_destroy(LinphoneAuthInfo *info);

/**
 * @}
 */


/**
 * @addtogroup initializing
 * @{
**/

/**
 * LinphoneGlobalState describes the global state of the LinphoneCore object.
 * It is notified via the LinphoneCoreVTable::global_state_changed
**/
typedef enum _LinphoneGlobalState{
	LinphoneGlobalOff,
	LinphoneGlobalStartup,
	LinphoneGlobalOn,
	LinphoneGlobalShutdown
}LinphoneGlobalState;

const char *linphone_global_state_to_string(LinphoneGlobalState gs);


/**Call state notification callback prototype*/
typedef void (*LinphoneGlobalStateCb)(struct _LinphoneCore *lc, LinphoneGlobalState gstate, const char *message);
/**Call state notification callback prototype*/
typedef void (*LinphoneCallStateCb)(struct _LinphoneCore *lc, LinphoneCall *call, LinphoneCallState cstate, const char *message);
/**Call encryption changed callback prototype*/
typedef void (*CallEncryptionChangedCb)(struct _LinphoneCore *lc, LinphoneCall *call, bool_t on, const char *authentication_token);

/** @ingroup Proxies
 * Registration state notification callback prototype
 * */
typedef void (*LinphoneRegistrationStateCb)(struct _LinphoneCore *lc, LinphoneProxyConfig *cfg, LinphoneRegistrationState cstate, const char *message);
/** Callback prototype */
typedef void (*ShowInterfaceCb)(struct _LinphoneCore *lc);
/** Callback prototype */
typedef void (*DisplayStatusCb)(struct _LinphoneCore *lc, const char *message);
/** Callback prototype */
typedef void (*DisplayMessageCb)(struct _LinphoneCore *lc, const char *message);
/** Callback prototype */
typedef void (*DisplayUrlCb)(struct _LinphoneCore *lc, const char *message, const char *url);
/** Callback prototype */
typedef void (*LinphoneCoreCbFunc)(struct _LinphoneCore *lc,void * user_data);
/** Callback prototype */
typedef void (*NotifyReceivedCb)(struct _LinphoneCore *lc, LinphoneCall *call, const char *from, const char *event);
/**
 * Report status change for a friend previously \link linphone_core_add_friend() added \endlink to #LinphoneCore.
 * @param lc #LinphoneCore object .
 * @param lf Updated #LinphoneFriend .
 */
//typedef void (*NotifyPresenceReceivedCb)(struct _LinphoneCore *lc, LinphoneFriend * lf);
/**
 *  Reports that a new subscription request has been received and wait for a decision.
 *  <br> Status on this subscription request is notified by \link linphone_friend_set_inc_subscribe_policy() changing policy \endlink for this friend
 *	@param lc #LinphoneCore object
 *	@param lf #LinphoneFriend corresponding to the subscriber
 *	@param url of the subscriber
 *  Callback prototype
 *  */
//typedef void (*NewSubscribtionRequestCb)(struct _LinphoneCore *lc, LinphoneFriend *lf, const char *url);
/** Callback prototype */
typedef void (*AuthInfoRequested)(struct _LinphoneCore *lc, const char *realm, const char *username);
/** Callback prototype */
typedef void (*CallLogUpdated)(struct _LinphoneCore *lc, struct _LinphoneCallLog *newcl);
/**
 * Callback prototype
 * @deprecated use #MessageReceived instead.
 *
 * @param lc #LinphoneCore object
 * @param room #LinphoneChatRoom involved in this conversation. Can be be created by the framework in case \link #LinphoneAddress the from \endlink is not present in any chat room.
 * @param from #LinphoneAddress from
 * @param message incoming message
 *  */
//typedef void (*TextMessageReceived)(LinphoneCore *lc, LinphoneChatRoom *room, const LinphoneAddress *from, const char *message);
/**
 * Chat message callback prototype
 *
 * @param lc #LinphoneCore object
 * @param room #LinphoneChatRoom involved in this conversation. Can be be created by the framework in case \link #LinphoneAddress the from \endlink is not present in any chat room.
 * @param LinphoneChatMessage incoming message
 * */
//typedef void (*MessageReceived)(LinphoneCore *lc, LinphoneChatRoom *room, LinphoneChatMessage *message);
	
/** Callback prototype */
typedef void (*DtmfReceived)(struct _LinphoneCore* lc, LinphoneCall *call, int dtmf);
/** Callback prototype */
typedef void (*ReferReceived)(struct _LinphoneCore *lc, const char *refer_to);
/** Callback prototype */
//typedef void (*BuddyInfoUpdated)(struct _LinphoneCore *lc, LinphoneFriend *lf);
/** Callback prototype for in progress transfers. The new_call_state is the state of the call resulting of the transfer, at the other party. */
typedef void (*LinphoneTransferStateChanged)(struct _LinphoneCore *lc, LinphoneCall *transfered, LinphoneCallState new_call_state);
/** Callback prototype for receiving quality statistics for calls*/
//typedef void (*CallStatsUpdated)(struct _LinphoneCore *lc, LinphoneCall *call, const LinphoneCallStats *stats);

/**
 * This structure holds all callbacks that the application should implement.
 *  None is mandatory.
**/
typedef struct _LinphoneVTable{
	LinphoneGlobalStateCb global_state_changed; /**<Notifies globlal state changes*/
	LinphoneRegistrationStateCb registration_state_changed;/**<Notifies registration state changes*/
	LinphoneCallStateCb call_state_changed;/**<Notifies call state changes*/
	//NotifyPresenceReceivedCb notify_presence_recv; /**< Notify received presence events*/
	//NewSubscribtionRequestCb new_subscription_request; /**< Notify about pending subscription request */
	AuthInfoRequested auth_info_requested; /**< Ask the application some authentication information */
	CallLogUpdated call_log_updated; /**< Notifies that call log list has been updated */
	//TextMessageReceived text_received; /** @deprecated, use #message_received instead <br> A text message has been received */
	//MessageReceived message_received; /** a message is received, can be text or external body*/
	DtmfReceived dtmf_received; /**< A dtmf has been received received */
	ReferReceived refer_received; /**< An out of call refer was received */
	CallEncryptionChangedCb call_encryption_changed; /**<Notifies on change in the encryption of call streams */
	LinphoneTransferStateChanged transfer_state_changed; /**<Notifies when a transfer is in progress */
	//BuddyInfoUpdated buddy_info_updated; /**< a LinphoneFriend's BuddyInfo has changed*/
	NotifyReceivedCb notify_recv; /**< Other notifications*/
	//CallStatsUpdated call_stats_updated; /**<Notifies on refreshing of call's statistics. */
	DisplayStatusCb display_status; /**< DEPRECATED Callback that notifies various events with human readable text.*/
	DisplayMessageCb display_message;/**< DEPRECATED Callback to display a message to the user */
	DisplayMessageCb display_warning;/**< DEPRECATED Callback to display a warning to the user */
	DisplayUrlCb display_url; /**< DEPRECATED */
	ShowInterfaceCb show; /**< DEPRECATED Notifies the application that it should show up*/
} LinphoneCoreVTable;

/**
 * @}
**/

typedef struct _LCCallbackObj
{
  LinphoneCoreCbFunc _func;
  void * _user_data;
}LCCallbackObj;



typedef enum _LinphoneFirewallPolicy{
	LinphonePolicyNoFirewall,
	LinphonePolicyUseNatAddress,
	LinphonePolicyUseStun,
	LinphonePolicyUseIce,
	LinphonePolicyUseUpnp,
} LinphoneFirewallPolicy;

typedef enum _LinphoneWaitingState{
	LinphoneWaitingStart,
	LinphoneWaitingProgress,
	LinphoneWaitingFinished
} LinphoneWaitingState;
typedef void * (*LinphoneWaitingCallback)(struct _LinphoneCore *lc, void *context, LinphoneWaitingState ws, const char *purpose, float progress);


/* THE main API */

/**
 * Define a log handler.
 *
 * @ingroup misc
 *
 * @param logfunc The function pointer of the log handler.
 */
void linphone_core_set_log_handler(OrtpLogFunc logfunc);
/**
 * Define a log file.
 *
 * @ingroup misc
 *
 * If the file pointer passed as an argument is NULL, stdout is used instead.
 *
 * @param file A pointer to the FILE structure of the file to write to.
 */
void linphone_core_set_log_file(FILE *file);
/**
 * Define the log level.
 *
 * @ingroup misc
 *
 * The loglevel parameter is a bitmask parameter. Therefore to enable only warning and error
 * messages, use ORTP_WARNING | ORTP_ERROR. To disable logs, simply set loglevel to 0.
 *
 * @param loglevel A bitmask of the log levels to set.
 */
void linphone_core_set_log_level(OrtpLogLevel loglevel);
void linphone_core_enable_logs(FILE *file);
void linphone_core_enable_logs_with_cb(OrtpLogFunc logfunc);
void linphone_core_disable_logs(void);
const char *linphone_core_get_version(void);
const char *linphone_core_get_user_agent_name(void);
const char *linphone_core_get_user_agent_version(void);

LinphoneCore *linphone_core_new(const LinphoneCoreVTable *vtable, void* userdata);

/**
 * Instantiates a LinphoneCore object with a given LpConfig.
 * @ingroup initializing
 *
 * The LinphoneCore object is the primary handle for doing all phone actions.
 * It should be unique within your application.
 * @param vtable a LinphoneCoreVTable structure holding your application callbacks
 * @param config a pointer to an LpConfig object holding the configuration of the LinphoneCore to be instantiated.
 * @param userdata an opaque user pointer that can be retrieved at any time (for example in
 *        callbacks) using linphone_core_get_user_data().
 * @see linphone_core_new
**/
LinphoneCore *linphone_core_new_with_config(const LinphoneCoreVTable *vtable, void *userdata);

/* function to be periodically called in a main loop */
/* For ICE to work properly it should be called every 20ms */
void linphone_core_iterate(LinphoneCore *lc);

#if 0 /*not implemented yet*/
/**
 * @ingroup initializing
 * Provide Linphone Core with an unique identifier. This be later used to identified contact address coming from this device.
 * Value is not saved.
 * @param lc object
 * @param string identifying the device, can be EMEI or UDID
 *
 */
void linphone_core_set_device_identifier(LinphoneCore *lc,const char* device_id);
/**
 * @ingroup initializing
 * get Linphone unique identifier
 *
 */
const char*  linphone_core_get_device_identifier(const LinphoneCore *lc);

#endif

/*sets the user-agent string in sip messages, ideally called just after linphone_core_new() or linphone_core_init() */
void linphone_core_set_user_agent(LinphoneCore *lc, const char *ua_name, const char *version);

LinphoneAddress * linphone_core_interpret_url(LinphoneCore *lc, const char *url);

LinphoneCall * linphone_core_invite(LinphoneCore *lc, const char *url);

LinphoneCall * linphone_core_invite_sdp(LinphoneCore *lc, const char *url, const char *offer);

LinphoneCall * linphone_core_invite_address(LinphoneCore *lc, const LinphoneAddress *addr);

LinphoneCall * linphone_core_invite_with_params(LinphoneCore *lc, const char *url, const LinphoneCallParams *params);

LinphoneCall * linphone_core_invite_address_with_params(LinphoneCore *lc, const LinphoneAddress *addr, const LinphoneCallParams *params, const char* offer);

int linphone_core_transfer_call(LinphoneCore *lc, LinphoneCall *call, const char *refer_to);

int linphone_core_transfer_call_to_another(LinphoneCore *lc, LinphoneCall *call, LinphoneCall *dest);

bool_t linphone_core_inc_invite_pending(LinphoneCore*lc);

bool_t linphone_core_in_call(const LinphoneCore *lc);

LinphoneCall *linphone_core_get_current_call(const LinphoneCore *lc);

int linphone_core_accept_call(LinphoneCore *lc, LinphoneCall *call);

int linphone_core_accept_call_with_params(LinphoneCore *lc, LinphoneCall *call, const LinphoneCallParams *params);

int linphone_core_terminate_call(LinphoneCore *lc, LinphoneCall *call);

int linphone_core_redirect_call(LinphoneCore *lc, LinphoneCall *call, const char *redirect_uri);

int linphone_core_decline_call(LinphoneCore *lc, LinphoneCall * call, LinphoneReason reason);

int linphone_core_terminate_all_calls(LinphoneCore *lc);

int linphone_core_pause_call(LinphoneCore *lc, LinphoneCall *call);

int linphone_core_pause_all_calls(LinphoneCore *lc);

int linphone_core_resume_call(LinphoneCore *lc, LinphoneCall *call);

int linphone_core_update_call(LinphoneCore *lc, LinphoneCall *call, const LinphoneCallParams *params);

int linphone_core_defer_call_update(LinphoneCore *lc, LinphoneCall *call);

int linphone_core_accept_call_update(LinphoneCore *lc, LinphoneCall *call, const LinphoneCallParams *params);

int linphone_core_abort_call(LinphoneCore *lc, LinphoneCall *call, const char *error);

/**
 * @ingroup media_parameters
 * Get default call parameters reflecting current linphone core configuration
 * @param LinphoneCore object
 * @return  LinphoneCallParams
 */
LinphoneCallParams *linphone_core_create_default_call_parameters(LinphoneCore *lc);

LinphoneCall *linphone_core_get_call_by_remote_address(LinphoneCore *lc, const char *remote_address);

void linphone_core_send_dtmf(LinphoneCore *lc,char dtmf);

int linphone_core_set_primary_contact(LinphoneCore *lc, const char *contact);

const char *linphone_core_get_primary_contact(LinphoneCore *lc);

const char * linphone_core_get_identity(LinphoneCore *lc);

bool_t linphone_core_ipv6_enabled(LinphoneCore *lc);
void linphone_core_enable_ipv6(LinphoneCore *lc, bool_t val);

LinphoneAddress *linphone_core_get_primary_contact_parsed(LinphoneCore *lc);
const char * linphone_core_get_identity(LinphoneCore *lc);

/**
 * @ingroup proxy 
 *Create a proxy config with default value from Linphone core.
 *@param lc #LinphoneCore object
 *@return #LinphoneProxyConfig with defualt value set 
 */
LinphoneProxyConfig * linphone_core_create_proxy_config(LinphoneCore *lc);
	
int linphone_core_add_proxy_config(LinphoneCore *lc, LinphoneProxyConfig *config);

void linphone_core_clear_proxy_config(LinphoneCore *lc);

void linphone_core_remove_proxy_config(LinphoneCore *lc, LinphoneProxyConfig *config);

const MSList *linphone_core_get_proxy_config_list(const LinphoneCore *lc);

void linphone_core_set_default_proxy(LinphoneCore *lc, LinphoneProxyConfig *config);

void linphone_core_set_default_proxy_index(LinphoneCore *lc, int index);

int linphone_core_get_default_proxy(LinphoneCore *lc, LinphoneProxyConfig **config);

void linphone_core_add_auth_info(LinphoneCore *lc, const LinphoneAuthInfo *info);

void linphone_core_remove_auth_info(LinphoneCore *lc, const LinphoneAuthInfo *info);

const MSList *linphone_core_get_auth_info_list(const LinphoneCore *lc);

const LinphoneAuthInfo *linphone_core_find_auth_info(LinphoneCore *lc, const char *realm, const char *username);

void linphone_core_abort_authentication(LinphoneCore *lc,  LinphoneAuthInfo *info);

void linphone_core_clear_all_auth_info(LinphoneCore *lc);

void linphone_core_set_sip_port(LinphoneCore *lc, int port);

int linphone_core_get_sip_port(LinphoneCore *lc);

int linphone_core_set_sip_transports(LinphoneCore *lc, const LCSipTransports *transports);

int linphone_core_get_sip_transports(LinphoneCore *lc, LCSipTransports *transports);

void linphone_core_set_inc_timeout(LinphoneCore *lc, int seconds);

int linphone_core_get_inc_timeout(LinphoneCore *lc);

void linphone_core_set_in_call_timeout(LinphoneCore *lc, int seconds);

int linphone_core_get_in_call_timeout(LinphoneCore *lc);

void linphone_core_set_delayed_timeout(LinphoneCore *lc, int seconds);

int linphone_core_get_delayed_timeout(LinphoneCore *lc);

int linphone_core_set_sip_random_port(LinphoneCore *lc, bool_t val);

bool_t linphone_core_get_sip_random_port(LinphoneCore *lc);

void linphone_core_set_nat_address(LinphoneCore *lc, const char *addr);

const char *linphone_core_get_nat_address(const LinphoneCore *lc);

void linphone_core_set_firewall_policy(LinphoneCore *lc, LinphoneFirewallPolicy pol);

LinphoneFirewallPolicy linphone_core_get_firewall_policy(const LinphoneCore *lc);

const char * linphone_core_get_relay_addr(const LinphoneCore *lc);

int linphone_core_set_relay_addr(LinphoneCore *lc, const char *addr);

void linphone_core_update_proxy_register(LinphoneCore *lc);
void linphone_core_refresh_subscribes(LinphoneCore *lc);

/* returns a list of LinphoneCallLog */
const MSList * linphone_core_get_call_logs(LinphoneCore *lc);
void linphone_core_clear_call_logs(LinphoneCore *lc);
int linphone_core_get_missed_calls_count(LinphoneCore *lc);
void linphone_core_reset_missed_calls_count(LinphoneCore *lc);
void linphone_core_remove_call_log(LinphoneCore *lc, LinphoneCallLog *call_log);

int linphone_core_get_current_call_duration(const LinphoneCore *lc);

bool_t linphone_core_media_description_contains_video_stream(const SalMediaDescription *md);

/**
 * @ingroup network_parameters
 * This method is called by the application to notify the linphone core library when network is reachable.
 * Calling this method with true trigger linphone to initiate a registration process for all proxies.
 * Calling this method disables the automatic network detection mode. It means you must call this method after each network state changes.
 */
void linphone_core_set_network_reachable(LinphoneCore* lc,bool_t value);
/**
 * @ingroup network_parameters
 * return network state either as positioned by the application or by linphone itself.
 */
bool_t linphone_core_is_network_reachable(LinphoneCore* lc);

/**
 *  @ingroup network_parameters
 *  enable signaling keep alive. small udp packet sent periodically to keep udp NAT association
 */
void linphone_core_enable_keep_alive(LinphoneCore* lc,bool_t enable);
/**
 *  @ingroup network_parameters
 * Is signaling keep alive
 */
bool_t linphone_core_keep_alive_enabled(LinphoneCore* lc);

void *linphone_core_get_user_data(LinphoneCore *lc);
void linphone_core_set_user_data(LinphoneCore *lc, void *userdata);


/*set a callback for some blocking operations, it takes you informed of the progress of the operation*/
void linphone_core_set_waiting_callback(LinphoneCore *lc, LinphoneWaitingCallback cb, void *user_context);


void linphone_core_destroy(LinphoneCore *lc);

int linphone_core_get_calls_nb(const LinphoneCore *lc);

const MSList *linphone_core_get_calls(LinphoneCore *lc);

LinphoneGlobalState linphone_core_get_global_state(const LinphoneCore *lc);

/**
 * force registration refresh to be initiated upon next iterate
 * @ingroup proxies
 */
void linphone_core_refresh_registers(LinphoneCore* lc);

/**
 * Search from the list of current calls if a remote address match uri
 * @ingroup call_control
 * @param lc
 * @param uri which should match call remote uri
 * @return LinphoneCall or NULL is no match is found
 */
const LinphoneCall* linphone_core_find_call_from_uri(LinphoneCore *lc, const char *uri);

/**
 * Get the maximum number of simultaneous calls Linphone core can manage at a time. All new call above this limit are declined with a busy answer
 * @ingroup initializing
 * @param lc core
 * @return max number of simultaneous calls
 */
int linphone_core_get_max_calls(LinphoneCore *lc);
/**
 * Set the maximum number of simultaneous calls Linphone core can manage at a time. All new call above this limit are declined with a busy answer
 * @ingroup initializing
 * @param lc core
 * @param max number of simultaneous calls
 */
void linphone_core_set_max_calls(LinphoneCore *lc, int max);

/**
 * Init call params using LinphoneCore's current configuration
 */
void linphone_core_init_default_params(LinphoneCore*lc, LinphoneCallParams *params);

void linphone_core_set_sip_dscp(LinphoneCore *lc, int dscp);
int linphone_core_get_sip_dscp(const LinphoneCore *lc);

typedef bool_t(*LinphoneCoreIterateHook)(void *data);

void linphone_core_add_iterate_hook(LinphoneCore *lc, LinphoneCoreIterateHook hook, void *hook_data);

void linphone_core_remove_iterate_hook(LinphoneCore *lc, LinphoneCoreIterateHook hook, void *hook_data);

#ifdef __cplusplus
}
#endif


#endif
