/*
linphone
Copyright (C) 2000  Simon MORLAT (simon.morlat@linphone.org)

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

#define _GNU_SOURCE
#include "linphonecore.h"
#include "private.h"

#include <math.h>

#ifdef INET6
#ifndef WIN32
#include <netdb.h>
#endif
#endif

#include "liblinphone_gitversion.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment (lib,"WS2_32")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <time.h>
#endif

static const char *liblinphone_version=
#ifdef LIBLINPHONE_GIT_VERSION
	LIBLINPHONE_GIT_VERSION
#else
	LIBLINPHONE_VERSION
#endif
;

static void set_network_reachable(LinphoneCore* lc,bool_t isReachable, time_t curtime);
static void linphone_core_run_hooks(LinphoneCore *lc);
static void linphone_core_free_hooks(LinphoneCore *lc);

const char *linphone_core_get_nat_address_resolved(LinphoneCore *lc);

extern SalCallbacks linphone_sal_callbacks;

void lc_callback_obj_init(LCCallbackObj *obj,LinphoneCoreCbFunc func,void* ud)
{
  obj->_func=func;
  obj->_user_data=ud;
}

int lc_callback_obj_invoke(LCCallbackObj *obj, LinphoneCore *lc){
	if (obj->_func!=NULL) obj->_func(lc,obj->_user_data);
	return 0;
}

/************************************************************************/
/*    Generate random port                                                                  */
/************************************************************************/
int init_sockets()
{
#ifdef WIN32
	WORD version;
	WSADATA wsaData;

	version = MAKEWORD(1, 1);

	WSAStartup(version, &wsaData);
#endif
	return 0;
}

int release_sockets()
{
#ifdef WIN32
	WSACleanup();
#endif
	return 0;
}

int generate_random_port()
{
	int nFreePort = -1;
	int nSocket = -1;
	socklen_t nSocketLen = 0;

#ifndef AF_IPV6
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(0);
	sin.sin_addr.s_addr = htonl(INADDR_ANY);

	nSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (nSocket < 0) {
		perror("socket()");
		return -1;
	}

	if (bind(nSocket, (struct sockaddr *)&sin, sizeof(sin)) != 0)
	{
		perror("bind()");
#if defined(_WIN32)
		closesocket(nSocket);
#else
		close(nSocket);
#endif
		return -1;
	}

	nSocketLen = sizeof(sin);
	if (getsockname(nSocket, (struct sockaddr *)&sin, &nSocketLen) != 0)
	{
		perror("getsockname()");
#if defined(_WIN32)
		closesocket(nSocket);
#else
		close(nSocket);
#endif
		return -1;
	}

	nFreePort = sin.sin_port;
	if (nSocket != -1) {
#if defined(_WIN32)
		closesocket(nSocket);
#else
		close(nSocket);
#endif
	}

#else
	struct sockaddr_in6 sin6;
	memset(&sin6, 0, sizeof(sin6));
	sin.sin_family = AF_INET6;
	sin.sin_port = htons(0);
	sin6.sin_addr.s_addr = htonl(IN6ADDR_ANY);

	nSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

	if (nSocket < 0) {
		perror("socket()");
		return -1;
	}

	if (bind(nSocket, (struct sockaddr *)&sin6, sizeof(sin6)) != 0)
	{
		perror("bind()");
#if defined(_WIN32)
		closesocket(nSocket);
#else
		close(nSocket);
#endif
		return -1;
	}

	nSocketLen = sizeof(sin6);
	if (getsockname(nSocket, (struct sockaddr *)&sin6, &nSocketLen) != 0)
	{
		perror("getsockname()");
#if defined(_WIN32)
		closesocket(nSocket);
#else
		close(nSocket);
#endif
		return -1;
	}

	nFreePort = sin6.sin6_port;

	if (nSocket != -1) {
#if defined(_WIN32)
		closesocket(nSocket);
#else
		close(nSocket);
#endif
	}

#endif
	return nFreePort;
}
/***************************** end *******************************************/

/*prevent a gcc bug with %c*/
static size_t my_strftime(char *s, size_t max, const char  *fmt,  const struct tm *tm){
	return strftime(s, max, fmt, tm);
}

static void set_call_log_date(LinphoneCallLog *cl, time_t start_time){
	struct tm loctime;
#ifdef WIN32
#if !defined(_WIN32_WCE)
	loctime=*localtime(&start_time);
	/*FIXME*/
#endif /*_WIN32_WCE*/
#else
	localtime_r(&start_time,&loctime);
#endif
	my_strftime(cl->start_date,sizeof(cl->start_date),"%c",&loctime);
}

LinphoneCallLog * linphone_call_log_new(LinphoneCall *call, LinphoneAddress *from, LinphoneAddress *to){
	LinphoneCallLog *cl=ms_new0(LinphoneCallLog,1);
	cl->dir=call->dir;
	cl->start_date_time=call->start_time;
	set_call_log_date(cl,cl->start_date_time);
	cl->from=from;
	cl->to=to;
	cl->status=LinphoneCallAborted; /*default status*/
	cl->quality=-1;
	return cl;
}


static time_t string_to_time(const char *date){
#ifndef WIN32
	struct tm tmtime={0};
	strptime(date,"%c",&tmtime);
	return mktime(&tmtime);
#else
	return 0;
#endif
}

/**
 * @addtogroup call_logs
 * @{
**/

/**
 * Returns a human readable string describing the call.
 *
 * @note: the returned char* must be freed by the application (use ms_free()).
**/
char * linphone_call_log_to_str(LinphoneCallLog *cl){
	char *status;
	char *tmp;
	char *from=linphone_address_as_string (cl->from);
	char *to=linphone_address_as_string (cl->to);
	switch(cl->status){
		case LinphoneCallAborted:
			status=_("aborted");
			break;
		case LinphoneCallSuccess:
			status=_("completed");
			break;
		case LinphoneCallMissed:
			status=_("missed");
			break;
		default:
			status="unknown";
	}
	tmp=ortp_strdup_printf(_("%s at %s\nFrom: %s\nTo: %s\nStatus: %s\nDuration: %i mn %i sec\n"),
			(cl->dir==LinphoneCallIncoming) ? _("Incoming call") : _("Outgoing call"),
			cl->start_date,
			from,
			to,
			status,
			cl->duration/60,
			cl->duration%60);
	ms_free(from);
	ms_free(to);
	return tmp;
}

const char *linphone_call_log_get_call_id(const LinphoneCallLog *cl){
	return cl->call_id;
}

/**
 * Assign a user pointer to the call log.
**/
void linphone_call_log_set_user_pointer(LinphoneCallLog *cl, void *up){
	cl->user_pointer=up;
}

/**
 * Returns the user pointer associated with the call log.
**/
void *linphone_call_log_get_user_pointer(const LinphoneCallLog *cl){
	return cl->user_pointer;
}


/**
 * Associate a persistent reference key to the call log.
 *
 * The reference key can be for example an id to an external database.
 * It is stored in the config file, thus can survive to process exits/restarts.
 *
**/
void linphone_call_log_set_ref_key(LinphoneCallLog *cl, const char *refkey){
	if (cl->refkey!=NULL){
		ms_free(cl->refkey);
		cl->refkey=NULL;
	}
	if (refkey) cl->refkey=ms_strdup(refkey);
}

/**
 * Get the persistent reference key associated to the call log.
 *
 * The reference key can be for example an id to an external database.
 * It is stored in the config file, thus can survive to process exits/restarts.
 *
**/
const char *linphone_call_log_get_ref_key(const LinphoneCallLog *cl){
	return cl->refkey;
}

/**
 * Returns origin (ie from) address of the call.
**/
LinphoneAddress *linphone_call_log_get_from(LinphoneCallLog *cl){
	return cl->from;
}

/**
 * Returns destination address (ie to) of the call.
**/
LinphoneAddress *linphone_call_log_get_to(LinphoneCallLog *cl){
	return cl->to;
}

/**
 * Returns remote address (that is from or to depending on call direction).
**/
LinphoneAddress *linphone_call_log_get_remote_address(LinphoneCallLog *cl){
	return (cl->dir == LinphoneCallIncoming) ? cl->from : cl->to;
}

/**
 * Returns the direction of the call.
**/
LinphoneCallDir linphone_call_log_get_dir(LinphoneCallLog *cl){
	return cl->dir;
}

/**
 * Returns the status of the call.
**/
LinphoneCallStatus linphone_call_log_get_status(LinphoneCallLog *cl){
	return cl->status;
}

/**
 * Returns the start date of the call, expressed as a POSIX time_t.
**/
time_t linphone_call_log_get_start_date(LinphoneCallLog *cl){
	return cl->start_date_time;
}

/**
 * Returns duration of the call.
**/
int linphone_call_log_get_duration(LinphoneCallLog *cl){
	return cl->duration;
}

/**
 * Returns overall quality indication of the call.
**/
float linphone_call_log_get_quality(LinphoneCallLog *cl){
	return cl->quality;
}

/**
 * return true if video was enabled at the end of the call
 */
LinphoneCallStatus linphone_call_log_video_enabled(LinphoneCallLog *cl) {
	return cl->video_enabled;
}
/** @} */

void linphone_call_log_destroy(LinphoneCallLog *cl){
	if (cl->from!=NULL) linphone_address_destroy(cl->from);
	if (cl->to!=NULL) linphone_address_destroy(cl->to);
	if (cl->refkey!=NULL) ms_free(cl->refkey);
	if (cl->call_id) ms_free(cl->call_id);
	ms_free(cl);
}

/**
 * Returns TRUE if the LinphoneCall asked to autoanswer
 *
**/
bool_t linphone_call_asked_to_autoanswer(LinphoneCall *call){
	//return TRUE if the unique(for the moment) incoming call asked to be autoanswered
	if(call)
		return sal_call_autoanswer_asked(call->op);
	else
		return FALSE;
}

int linphone_core_get_current_call_duration(const LinphoneCore *lc){
	LinphoneCall *call=linphone_core_get_current_call((LinphoneCore *)lc);
	if (call)  return linphone_call_get_duration(call);
	return -1;
}

bool_t linphone_core_media_description_contains_video_stream(const SalMediaDescription *md)
{
	int i;

	for (i = 0; i < md->n_active_streams; i++) {
		if (md->streams[i].type == SalVideo)
			return TRUE;
	}
	return FALSE;
}

const LinphoneAddress *linphone_core_get_current_call_remote_address(struct _LinphoneCore *lc){
	LinphoneCall *call=linphone_core_get_current_call(lc);
	if (call==NULL) return NULL;
	return linphone_call_get_remote_address(call);
}

void linphone_core_set_log_handler(OrtpLogFunc logfunc) {
	ortp_set_log_handler(logfunc);
}

void linphone_core_set_log_file(FILE *file) {
	if (file == NULL) file = stdout;
	ortp_set_log_file(file);
}

void linphone_core_set_log_level(OrtpLogLevel loglevel) {
	ortp_set_log_level_mask(loglevel);
}

/**
 * Enable logs in supplied FILE*.
 *
 * @ingroup misc
 * @deprecated Use #linphone_core_set_log_file and #linphone_core_set_log_level instead.
 *
 * @param file a C FILE* where to fprintf logs. If null stdout is used.
 *
**/
void linphone_core_enable_logs(FILE *file){
	if (file==NULL) file=stdout;
	ortp_set_log_file(file);
	ortp_set_log_level_mask(ORTP_MESSAGE|ORTP_WARNING|ORTP_ERROR|ORTP_FATAL);
}

/**
 * Enable logs through the user's supplied log callback.
 *
 * @ingroup misc
 * @deprecated Use #linphone_core_set_log_handler and #linphone_core_set_log_level instead.
 *
 * @param logfunc The address of a OrtpLogFunc callback whose protoype is
 *            	  typedef void (*OrtpLogFunc)(OrtpLogLevel lev, const char *fmt, va_list args);
 *
**/
void linphone_core_enable_logs_with_cb(OrtpLogFunc logfunc){
	ortp_set_log_level_mask(ORTP_MESSAGE|ORTP_WARNING|ORTP_ERROR|ORTP_FATAL);
	ortp_set_log_handler(logfunc);
}

/**
 * Entirely disable logging.
 *
 * @ingroup misc
 * @deprecated Use #linphone_core_set_log_level instead.
**/
void linphone_core_disable_logs(){
	ortp_set_log_level_mask(ORTP_ERROR|ORTP_FATAL);
}

static void sip_config_read(LinphoneCore *lc)
{
	LCSipTransports tr;
	int random_port = 0;

	/*for tuning or test*/
	lc->sip_conf.sdp_200_ack = FALSE;
	lc->sip_conf.register_only_when_network_is_up = TRUE;
	lc->sip_conf.register_only_when_upnp_is_ok = FALSE;
	lc->sip_conf.ping_with_options = FALSE;
	lc->sip_conf.auto_net_state_mon = FALSE;
	lc->sip_conf.keepalive_period = 60;
	lc->sip_conf.tcp_tls_keepalive = 0;
	
	memset(&tr, 0x00, sizeof(tr));
	/* default udp transport */
	tr.transport = LcTransportUDP;
	tr.udp_port = 5060;

	if (lc->sip_conf.sip_random_port)
	{
		random_port = generate_random_port();
	}

	if (random_port > 0) {
		tr.udp_port = random_port;
	}

	sal_use_session_timers(lc->sal,200);	
	sal_use_rport(lc->sal, TRUE);
	sal_use_101(lc->sal, TRUE);
	sal_reuse_authorization(lc->sal, TRUE);
	sal_expire_old_registration_contacts(lc->sal, TRUE);

	linphone_core_enable_ipv6(lc, FALSE);

	/*setting the dscp must be done before starting the transports, otherwise it is not taken into effect*/
	sal_set_dscp(lc->sal, linphone_core_get_sip_dscp(lc));
	
	/*start listening on ports*/
 	linphone_core_set_sip_transports(lc, &tr);

	linphone_core_set_inc_timeout(lc, 120);
	linphone_core_set_in_call_timeout(lc, 0);	
	linphone_core_set_delayed_timeout(lc, 4);

	/* get the default proxy */
	linphone_core_set_default_proxy_index(lc, -1);
	linphone_core_enable_keep_alive(lc, (lc->sip_conf.keepalive_period > 0));
	sal_use_double_registrations(lc->sal, TRUE);
	sal_use_dates(lc->sal, TRUE);
}

/**
 * Returns liblinphone's version as a string.
 *
 * @ingroup misc
 *
**/
const char * linphone_core_get_version(void){
	return liblinphone_version;
}

void linphone_core_set_state(LinphoneCore *lc, LinphoneGlobalState gstate, const char *message){
	lc->state=gstate;
	if (lc->vtable.global_state_changed){
		lc->vtable.global_state_changed(lc,gstate,message);
	}
}

static void misc_config_read (LinphoneCore *lc) {
	lc->max_call_logs = 15;
	lc->max_calls = NB_MAX_CALLS;
}

static void linphone_core_init (LinphoneCore * lc, const LinphoneCoreVTable *vtable, void * userdata)
{
	ortp_set_log_level_mask(0xff);

	ms_message("Initializing LinphoneCore %s", linphone_core_get_version());

	memset (lc, 0, sizeof (LinphoneCore));
	lc->data=userdata;

	memcpy(&lc->vtable,vtable,sizeof(LinphoneCoreVTable));

	linphone_core_set_state(lc,LinphoneGlobalStartup,"Starting up");
	
	ms_init();
	
	lc->sal = sal_init();
	sal_set_user_pointer(lc->sal,lc);
	sal_set_callbacks(lc->sal, &linphone_sal_callbacks);

  lc->network_last_check = 0;
  lc->network_last_status = FALSE;

	sip_config_read(lc); /* this will start eXosip*/

	lc->presence_mode=LinphoneStatusOnline;
	misc_config_read(lc);

	if (lc->vtable.display_status)
		lc->vtable.display_status(lc,_("Ready"));

	lc->auto_net_state_mon = lc->sip_conf.auto_net_state_mon;
	
	linphone_core_set_network_reachable(lc, TRUE);

	linphone_core_set_state(lc,LinphoneGlobalOn,"Ready");
}

/**
 * Instanciates a LinphoneCore object.
 * @ingroup initializing
 *
 * The LinphoneCore object is the primary handle for doing all phone actions.
 * It should be unique within your application.
 * @param vtable a LinphoneCoreVTable structure holding your application callbacks
 * @param config_path a path to a config file. If it does not exists it will be created.
 *        The config file is used to store all settings, call logs, friends, proxies... so that all these settings
 *	       become persistent over the life of the LinphoneCore object.
 *	       It is allowed to set a NULL config file. In that case LinphoneCore will not store any settings.
 * @param factory_config_path a path to a read-only config file that can be used to
 *        to store hard-coded preference such as proxy settings or internal preferences.
 *        The settings in this factory file always override the one in the normal config file.
 *        It is OPTIONAL, use NULL if unneeded.
 * @param userdata an opaque user pointer that can be retrieved at any time (for example in
 *        callbacks) using linphone_core_get_user_data().
 * @see linphone_core_new_with_config
**/
LinphoneCore *linphone_core_new(const LinphoneCoreVTable *vtable, void * userdata)
{
	return linphone_core_new_with_config(vtable, userdata);
}

LinphoneCore *linphone_core_new_with_config(const LinphoneCoreVTable *vtable, void *userdata)
{
	LinphoneCore *core = ms_new(LinphoneCore, 1);
	linphone_core_init(core, vtable, userdata);
	return core;
}

/**
 * Sets the local "from" identity.
 *
 * @ingroup proxies
 * This data is used in absence of any proxy configuration or when no
 * default proxy configuration is set. See LinphoneProxyConfig
**/
int linphone_core_set_primary_contact(LinphoneCore *lc, const char *contact)
{
	LinphoneAddress *ctt;

	if ((ctt=linphone_address_new(contact))==0) {
		ms_error("Bad contact url: %s",contact);
		return -1;
	}
	if (lc->sip_conf.contact!=NULL) ms_free(lc->sip_conf.contact);
	lc->sip_conf.contact=ms_strdup(contact);
	if (lc->sip_conf.guessed_contact!=NULL){
		ms_free(lc->sip_conf.guessed_contact);
		lc->sip_conf.guessed_contact=NULL;
	}
	linphone_address_destroy(ctt);
	return 0;
}


/*result must be an array of chars at least LINPHONE_IPADDR_SIZE */
void linphone_core_get_local_ip(LinphoneCore *lc, const char *dest, char *result){
	const char *ip;
	if (linphone_core_get_firewall_policy(lc)==LinphonePolicyUseNatAddress
	    && (ip=linphone_core_get_nat_address_resolved(lc))!=NULL){
		strncpy(result,ip,LINPHONE_IPADDR_SIZE);
		return;
	}

	if (linphone_core_get_local_ip_for(lc->sip_conf.ipv6_enabled ? AF_INET6 : AF_INET,dest,result)==0)
		return;

	/*else fallback to SAL routine that will attempt to find the most realistic interface */
	sal_get_default_local_ip(lc->sal,lc->sip_conf.ipv6_enabled ? AF_INET6 : AF_INET,result,LINPHONE_IPADDR_SIZE);
}

static void update_primary_contact(LinphoneCore *lc){
	char *guessed=NULL;
	char tmp[LINPHONE_IPADDR_SIZE];

	LinphoneAddress *url;
	if (lc->sip_conf.guessed_contact!=NULL){
		ms_free(lc->sip_conf.guessed_contact);
		lc->sip_conf.guessed_contact=NULL;
	}
	url=linphone_address_new(lc->sip_conf.contact);
	if (!url){
		ms_error("Could not parse identity contact !");
		url=linphone_address_new("sip:unknown@unkwownhost");
	}
	linphone_core_get_local_ip(lc, NULL, tmp);
	if (strcmp(tmp,"127.0.0.1")==0 || strcmp(tmp,"::1")==0 ){
		ms_warning("Local loopback network only !");
		lc->sip_conf.loopback_only=TRUE;
	}else lc->sip_conf.loopback_only=FALSE;
	linphone_address_set_domain(url,tmp);
	linphone_address_set_port_int(url,linphone_core_get_sip_port (lc));
	guessed=linphone_address_as_string(url);
	lc->sip_conf.guessed_contact=guessed;
	linphone_address_destroy(url);
}

/**
 * Returns the default identity when no proxy configuration is used.
 *
 * @ingroup proxies
**/
const char *linphone_core_get_primary_contact(LinphoneCore *lc){
	char *identity;

	if (lc->sip_conf.guess_hostname){
		if (lc->sip_conf.guessed_contact==NULL || lc->sip_conf.loopback_only){
			update_primary_contact(lc);
		}
		identity=lc->sip_conf.guessed_contact;
	}else{
		identity=lc->sip_conf.contact;
	}
	return identity;
}

/**
 * Same as linphone_core_get_primary_contact() but the result is a LinphoneAddress object
 * instead of const char*
 *
 * @ingroup proxies
**/
LinphoneAddress *linphone_core_get_primary_contact_parsed(LinphoneCore *lc){
	return linphone_address_new(linphone_core_get_primary_contact(lc));
}

static char _ua_name[64]="Linphone";
static char _ua_version[64] = LIBLINPHONE_GIT_VERSION;

#ifdef HAVE_EXOSIP_GET_VERSION
extern const char *eXosip_get_version();
#endif

static void apply_user_agent(LinphoneCore *lc){
	char ua_string[256];
	snprintf(ua_string,sizeof(ua_string)-1,"%s/%s (eXosip2/%s)", _ua_name, _ua_version,
#ifdef HAVE_EXOSIP_GET_VERSION
		 eXosip_get_version()
#else
		 "unknown"
#endif
	);
	if (lc->sal) sal_set_user_agent(lc->sal,ua_string);
}

/**
 * Sets the user agent string used in SIP messages.
 *
 * @ingroup misc
**/
void linphone_core_set_user_agent(LinphoneCore *lc, const char *name, const char *ver){
	strncpy(_ua_name,name,sizeof(_ua_name)-1);
	strncpy(_ua_version,ver,sizeof(_ua_version));
	apply_user_agent(lc);
}

const char *linphone_core_get_user_agent_name(void){
	return _ua_name;
}

const char *linphone_core_get_user_agent_version(void){
	return _ua_version;
}

static void transport_error(LinphoneCore *lc, const char* transport, int port){
	char *msg=ortp_strdup_printf("Could not start %s transport on port %i, maybe this port is already used.",transport,port);
	ms_warning("%s",msg);
	if (lc->vtable.display_warning)
		lc->vtable.display_warning(lc,msg);
	ms_free(msg);
}

static bool_t transports_unchanged(const LCSipTransports * tr1, const LCSipTransports * tr2){
	return
		tr2->transport == tr1->transport &&
		tr2->udp_port==tr1->udp_port &&
		tr2->tcp_port==tr1->tcp_port &&
		tr2->dtls_port==tr1->dtls_port &&
		tr2->tls_port==tr1->tls_port;
}

static int apply_transports(LinphoneCore *lc){
	Sal *sal=lc->sal;
	const char *anyaddr;
	LCSipTransports *tr=&lc->sip_conf.transports;

	/*first of all invalidate all current registrations so that we can register again with new transports*/
	__linphone_core_invalidate_registers(lc);
	
	if (lc->sip_conf.ipv6_enabled)
		anyaddr="::0";
	else
		anyaddr="0.0.0.0";

	sal_unlisten_ports(sal);
	switch (tr->transport)
	{
	case LcTransportTCP:
	{
		if (tr->tcp_port > 0) {
			if (sal_listen_port(sal, anyaddr, tr->tcp_port, SalTransportTCP, FALSE) != 0) {
				transport_error(lc, "tcp", tr->tcp_port);
				return -1;
			}
		}
	}
		break;

	case LcTransportTLS:
	{
		if (tr->tls_port > 0) {
			if (sal_listen_port(sal, anyaddr, tr->tls_port, SalTransportTLS, TRUE) != 0) {
				transport_error(lc, "tls", tr->tls_port);
				return -1;
			}
		}
	}
		break;

	case LcTransportDTLS:
	{
		if (tr->dtls_port > 0)
		{
			if (sal_listen_port(sal, anyaddr, tr->dtls_port, SalTransportDTLS, TRUE) != 0)
			{
				transport_error(lc, "dtls", tr->tls_port);
				return -1;
			}
		}
	}
		break;

	case LcTransportUDP:
	default:
	{
		if (tr->udp_port > 0) {
			if (sal_listen_port(sal, anyaddr, tr->udp_port, SalTransportUDP, FALSE) != 0) {
				transport_error(lc, "udp", tr->udp_port);
				return -1;
			}
		}
	}
		break;
	}

	apply_user_agent(lc);
	return 0;
}

/**
 * Sets the ports to be used for each of transport (UDP or TCP)
 *
 * A zero value port for a given transport means the transport
 * is not used.
 *
 * @ingroup network_parameters
**/
int linphone_core_set_sip_transports(LinphoneCore *lc, const LCSipTransports * tr){

	if (transports_unchanged(tr,&lc->sip_conf.transports))
		return 0;
	memcpy(&lc->sip_conf.transports,tr,sizeof(*tr));

	if (lc->sal==NULL) return 0;
	return apply_transports(lc);
}

/**
 * Retrieves the ports used for each transport (udp, tcp).
 * A zero value port for a given transport means the transport
 * is not used.
 * @ingroup network_parameters
**/
int linphone_core_get_sip_transports(LinphoneCore *lc, LCSipTransports *tr){
	memcpy(tr,&lc->sip_conf.transports,sizeof(*tr));
	return 0;
}

/**
 * Sets the UDP port to be used by SIP.
 *
 * Deprecated: use linphone_core_set_sip_transports() instead.
 * @ingroup network_parameters
**/
void linphone_core_set_sip_port(LinphoneCore *lc, int port)
{
	LCSipTransports tr;
	memset(&tr,0,sizeof(tr));

	linphone_core_get_sip_transports(lc, &tr);
	if (tr.transport == LcTransportTCP)
	{
		tr.tcp_port = port;
	}
	else if (tr.transport == LcTransportTLS)
	{
		tr.tls_port = port;
	}
	else if (tr.transport == LcTransportDTLS)
	{
		tr.dtls_port = port;
	}
	else
	{
		tr.udp_port = port;
	}
	linphone_core_set_sip_transports (lc,&tr);
}

/**
* Returns the UDP port used by SIP.
*
* Deprecated: use linphone_core_get_sip_transports() instead.
* @ingroup network_parameters
**/
int linphone_core_get_sip_port(LinphoneCore *lc)
{
	LCSipTransports *tr = &lc->sip_conf.transports;

	if (tr->transport == LcTransportTCP)
	{
		return tr->tcp_port;
	}
	else if (tr->transport == LcTransportTLS)
	{
		return tr->tls_port;
	}
	else if (tr->transport == LcTransportDTLS)
	{
		return tr->dtls_port;
	}
	else
	{
		return tr->udp_port;
	}
}

/**
 * Returns TRUE if IPv6 is enabled.
 *
 * @ingroup network_parameters
 * See linphone_core_enable_ipv6() for more details on how IPv6 is supported in liblinphone.
**/
bool_t linphone_core_ipv6_enabled(LinphoneCore *lc){
	return lc->sip_conf.ipv6_enabled;
}

/**
 * Turns IPv6 support on or off.
 *
 * @ingroup network_parameters
 *
 * @note IPv6 support is exclusive with IPv4 in liblinphone:
 * when IPv6 is turned on, IPv4 calls won't be possible anymore.
 * By default IPv6 support is off.
**/
void linphone_core_enable_ipv6(LinphoneCore *lc, bool_t val){
	if (lc->sip_conf.ipv6_enabled != val){
		lc->sip_conf.ipv6_enabled=val;
		if (lc->sal){
			/* we need to restart eXosip */
			apply_transports(lc);
		}
	}
}


static void monitor_network_state(LinphoneCore *lc, time_t curtime){
	char result[LINPHONE_IPADDR_SIZE];
	bool_t new_status=lc->network_last_status;

	/* only do the network up checking every five seconds */
	if (lc->network_last_check==0 || (curtime - lc->network_last_check) >= 5){
		linphone_core_get_local_ip_for(lc->sip_conf.ipv6_enabled ? AF_INET6 : AF_INET,NULL,result);
		if (strcmp(result,"::1")!=0 && strcmp(result,"127.0.0.1")!=0){
			new_status=TRUE;
		}else new_status=FALSE;

		lc->network_last_check = curtime;

		if (new_status!=lc->network_last_status) {
			if (new_status){
				ms_message("New local ip address is %s",result);
			}
			set_network_reachable(lc,new_status, curtime);
			lc->network_last_status=new_status;
		}
	}
}

static void proxy_update(LinphoneCore *lc){
	MSList *elem,*next;
	ms_list_for_each(lc->sip_conf.proxies,(void (*)(void*))&linphone_proxy_config_update);
	for(elem=lc->sip_conf.deleted_proxies;elem!=NULL;elem=next){
		LinphoneProxyConfig* cfg = (LinphoneProxyConfig*)elem->data;
		next=elem->next;
		if (ms_time(NULL) - cfg->deletion_date > 5) {
			lc->sip_conf.deleted_proxies =ms_list_remove_link(lc->sip_conf.deleted_proxies,elem);
			ms_message("clearing proxy config for [%s]",linphone_proxy_config_get_addr(cfg));
			linphone_proxy_config_destroy(cfg);
		}
	}
}

/**
 * Main loop function. It is crucial that your application call it periodically.
 *
 * @ingroup initializing
 * linphone_core_iterate() performs various backgrounds tasks:
 * - receiving of SIP messages
 * - handles timers and timeout
 * - performs registration to proxies
 * - authentication retries
 * The application MUST call this function periodically, in its main loop.
 * Be careful that this function must be called from the same thread as
 * other liblinphone methods. If it is not the case make sure all liblinphone calls are
 * serialized with a mutex.
**/
void linphone_core_iterate(LinphoneCore *lc){
	MSList *calls;
	LinphoneCall *call;
	time_t curtime=time(NULL);
	int elapsed;
	bool_t one_second_elapsed=FALSE;

	if (curtime-lc->prevtime>=1){
		lc->prevtime=curtime;
		one_second_elapsed=TRUE;
	}
		
	sal_iterate(lc->sal);
	
	if (lc->auto_net_state_mon) monitor_network_state(lc,curtime);

	proxy_update(lc);

	//we have to iterate for each call
	calls= lc->calls;
	while(calls!= NULL){
		call = (LinphoneCall *)calls->data;
		elapsed = curtime - call->start_time;
		 /* get immediately a reference to next one in case the one
		 we are going to examine is destroy and removed during
		 linphone_core_start_invite() */
		calls=calls->next;
		if (call->state==LinphoneCallOutgoingInit && (elapsed>=lc->sip_conf.delayed_timeout)){
			/*start the call even if the OPTIONS reply did not arrive*/			
			linphone_core_start_invite(lc,call);
		}
		if (call->state==LinphoneCallIncomingReceived){
			//ms_message("incoming call ringing for %i seconds",elapsed);
			if (elapsed > lc->sip_conf.inc_timeout){
				LinphoneReason decline_reason;
				ms_message("incoming call timeout (%i)",lc->sip_conf.inc_timeout);
				decline_reason=lc->current_call ? LinphoneReasonBusy : LinphoneReasonDeclined;
				call->log->status=LinphoneCallMissed;
				call->reason=LinphoneReasonNotAnswered;
				linphone_core_decline_call(lc,call,decline_reason);
			}
		}
		if (lc->sip_conf.in_call_timeout > 0 && elapsed > lc->sip_conf.in_call_timeout) {
			ms_message("in call timeout (%i)",lc->sip_conf.in_call_timeout);
			linphone_core_terminate_call(lc,call);
		}
	}

	linphone_core_run_hooks(lc);

	if (lc->initial_subscribes_sent==FALSE && lc->netup_time!=0 &&
	    (curtime-lc->netup_time)>3){
		//linphone_core_send_initial_subscribes(lc);
		lc->initial_subscribes_sent=TRUE;
	}
}

/**
 * Interpret a call destination as supplied by the user, and returns a fully qualified
 * LinphoneAddress.
 * 
 * @ingroup call_control
 *
 * A sip address should look like DisplayName <sip:username@domain:port> .
 * Basically this function performs the following tasks
 * - if a phone number is entered, prepend country prefix of the default proxy
 *   configuration, eventually escape the '+' by 00.
 * - if no domain part is supplied, append the domain name of the default proxy
 * - if no sip: is present, prepend it
 *
 * The result is a syntaxically correct SIP address.
**/

LinphoneAddress * linphone_core_interpret_url(LinphoneCore *lc, const char *url){
	
	LinphoneProxyConfig *proxy=lc->default_proxy;;
	char *tmpurl;
	LinphoneAddress *uri;

	/* check if we have a "sip:" */
	if (strstr(url,"sip:")==NULL){
		/* this doesn't look like a true sip uri */
		if (strchr(url,'@')!=NULL){
			/* seems like sip: is missing !*/
			tmpurl=ms_strdup_printf("sip:%s",url);
			uri=linphone_address_new(tmpurl);
			ms_free(tmpurl);
			if (uri){
				return uri;
			}
		}

		if (proxy!=NULL){
			/* append the proxy domain suffix */
			const char *identity=linphone_proxy_config_get_identity(proxy);
			uri=linphone_address_new(identity);
			if (uri==NULL){
				return NULL;
			}
			linphone_address_set_display_name(uri,NULL);
			linphone_address_set_username(uri, url);
			return uri;
		}else return NULL;
	}
	uri=linphone_address_new(url);
	if (uri!=NULL){
		return uri;
	}
	/* else we could not do anything with url given by user, so display an error */
	if (lc->vtable.display_warning!=NULL){
		lc->vtable.display_warning(lc,_("Could not parse given sip address. A sip url usually looks like sip:user@domain"));
	}
	return NULL;
}

/**
 * Returns the default identity SIP address.
 *
 * @ingroup proxies
 * This is an helper function:
 *
 * If no default proxy is set, this will return the primary contact (
 * see linphone_core_get_primary_contact() ). If a default proxy is set
 * it returns the registered identity on the proxy.
**/
const char * linphone_core_get_identity(LinphoneCore *lc){
	LinphoneProxyConfig *proxy=NULL;
	const char *from = NULL;
	linphone_core_get_default_proxy(lc,&proxy);
	if (proxy!=NULL) {
		from = linphone_proxy_config_get_identity(proxy);
	}
	return from;
}

const char * linphone_core_get_route(LinphoneCore *lc){
	LinphoneProxyConfig *proxy=NULL;
	const char *route=NULL;
	linphone_core_get_default_proxy(lc,&proxy);
	if (proxy!=NULL) {
		route=linphone_proxy_config_get_route(proxy);
	}
	return route;
}

void linphone_core_start_refered_call(LinphoneCore *lc, LinphoneCall *call){
	if (call->refer_pending){
		LinphoneCallParams *cp=linphone_core_create_default_call_parameters(lc);
		LinphoneCall *newcall;
		cp->referer=call;
		ms_message("Starting new call to refered address %s",call->refer_to);
		call->refer_pending=FALSE;
		newcall=linphone_core_invite_with_params(lc,call->refer_to,cp);
		linphone_call_params_destroy(cp);
		if (newcall) linphone_core_notify_refer_state(lc,call,newcall);
	}
}

void linphone_core_notify_refer_state(LinphoneCore *lc, LinphoneCall *referer, LinphoneCall *newcall){
	if (referer->op!=NULL){
		sal_call_notify_refer_state(referer->op, newcall ? newcall->op : NULL);
	}
}

LinphoneProxyConfig * linphone_core_lookup_known_proxy(LinphoneCore *lc, const LinphoneAddress *uri){
	const MSList *elem;
	LinphoneProxyConfig *found_cfg=NULL;
	LinphoneProxyConfig *default_cfg=lc->default_proxy;

	/*always prefer the default proxy if it is matching the destination uri*/
	if (default_cfg){
		const char *domain=linphone_proxy_config_get_domain(default_cfg);
		if (strcmp(domain,linphone_address_get_domain(uri))==0)
			return default_cfg;
	}

	/*otherwise iterate through the other proxy config and return the first matching*/
	for (elem=linphone_core_get_proxy_config_list(lc);elem!=NULL;elem=elem->next){
		LinphoneProxyConfig *cfg=(LinphoneProxyConfig*)elem->data;
		const char *domain=linphone_proxy_config_get_domain(cfg);
		if (domain!=NULL && strcmp(domain,linphone_address_get_domain(uri))==0){
			found_cfg=cfg;
			break;
		}
	}
	return found_cfg;
}

const char *linphone_core_find_best_identity(LinphoneCore *lc, const LinphoneAddress *to, const char **route){
	LinphoneProxyConfig *cfg=linphone_core_lookup_known_proxy(lc,to);
	if (cfg == NULL)
		linphone_core_get_default_proxy (lc,&cfg);

	if (cfg != NULL){
		if (route) *route=linphone_proxy_config_get_route(cfg);
		return linphone_proxy_config_get_identity (cfg);
	}

	return NULL;
}

static char *get_fixed_contact(LinphoneCore *lc, LinphoneCall *call , LinphoneProxyConfig *dest_proxy){
	LinphoneAddress *ctt;
	const char *localip=call->localip;

	/* first use user's supplied ip address if asked*/
	if (linphone_core_get_firewall_policy(lc)==LinphonePolicyUseNatAddress){
		ctt=linphone_core_get_primary_contact_parsed(lc);
		return ms_strdup_printf("sip:%s@%s",linphone_address_get_username(ctt),
		    	linphone_core_get_nat_address_resolved(lc));
	}

	/* if already choosed, don't change it */
	if (call->op && sal_op_get_contact(call->op)!=NULL){
		return NULL;
	}

	/* if the ping OPTIONS request succeeded use the contact guessed from the
	 received, rport*/
	if (call->ping_op){
		const char *guessed=sal_op_get_contact(call->ping_op);
		if (guessed){
			ms_message("Contact has been fixed using OPTIONS to %s",guessed);
			return ms_strdup(guessed);
		}
	}

	/*if using a proxy, use the contact address as guessed with the REGISTERs*/
	if (dest_proxy && dest_proxy->op){
		const char *fixed_contact = sal_op_get_contact(dest_proxy->op);
		if (fixed_contact) {
			ms_message("Contact has been fixed using proxy to %s",fixed_contact);
			return ms_strdup(fixed_contact);
		}
	}

	return NULL;
}

int linphone_core_proceed_with_invite_if_ready(LinphoneCore *lc, LinphoneCall *call, LinphoneProxyConfig *dest_proxy){
	bool_t ping_ready = FALSE;

	if (call->ping_op != NULL) {
		if (call->ping_replied == TRUE) ping_ready = TRUE;
	} else {
		ping_ready = TRUE;
	}

	if ((ping_ready == TRUE)) {
		return linphone_core_start_invite(lc, call);
	}
	return 0;
}

int linphone_core_start_invite(LinphoneCore *lc, LinphoneCall *call){
	int err;
	char *contact;
	char *real_url,*barmsg;
	char *from;
	LinphoneProxyConfig *dest_proxy=call->dest_proxy;

	/*try to be best-effort in giving real local or routable contact address */
	contact=get_fixed_contact(lc,call,dest_proxy);
	if (contact){
		sal_op_set_contact(call->op, contact);
		ms_free(contact);
	}
	
	/* fill sdp header */
	if (call->local_sdp != NULL)
	{
		if (!lc->sip_conf.sdp_200_ack) {
			call->media_pending = TRUE;
			sal_call_set_local_sdp(call->op, call->local_sdp);

			// need ?
			call->localdesc = sal_media_description_new();
			sal_media_decription_new_from_str(call->local_sdp, call->localdesc);			
			
			const char *me = linphone_core_get_identity(lc);
			LinphoneAddress *addr = linphone_address_new(me);
			const char *username = linphone_address_get_username(addr);
			strncpy(call->localdesc->addr, call->localip, sizeof(call->localdesc->addr));
			strncpy(call->localdesc->username, username, sizeof(call->localdesc->username));

			sal_call_set_local_media_description(call->op, call->localdesc);
		}
	}
	else {
		linphone_call_make_local_media_description(lc, call);
		if (!lc->sip_conf.sdp_200_ack) {
			call->media_pending = TRUE;
			sal_call_set_local_media_description(call->op, call->localdesc);
		}
	}

	real_url=linphone_address_as_string(call->log->to);
	from=linphone_address_as_string(call->log->from);

	err = sal_call(call->op, from, real_url);

	call->log->call_id=ms_strdup(sal_op_get_call_id(call->op)); /*must be known at that time*/

	if (lc->sip_conf.sdp_200_ack){
		call->media_pending=TRUE;
		if (call->local_sdp != NULL) {
			sal_call_set_local_sdp(call->op, call->local_sdp);

			call->localdesc = sal_media_description_new();
			sal_media_decription_new_from_str(call->local_sdp, call->localdesc);

			const char *me = linphone_core_get_identity(lc);
			LinphoneAddress *addr = linphone_address_new(me);
			const char *username = linphone_address_get_username(addr);
			strncpy(call->localdesc->addr, call->localip, sizeof(call->localdesc->addr));
			strncpy(call->localdesc->username, username, sizeof(call->localdesc->username));

			sal_call_set_local_media_description(call->op, call->localdesc);
		}
		else {
			sal_call_set_local_media_description(call->op, call->localdesc);
		}
	}
	barmsg=ortp_strdup_printf("%s %s", _("Contacting"), real_url);
	if (lc->vtable.display_status!=NULL)
		lc->vtable.display_status(lc,barmsg);
	ms_free(barmsg);

	if (err<0){
		if (lc->vtable.display_status!=NULL)
			lc->vtable.display_status(lc,_("Could not call"));
		linphone_call_set_state(call,LinphoneCallError,"Call failed");
	}else {
		linphone_call_set_state(call,LinphoneCallOutgoingProgress,"Outgoing call in progress");
	}
	ms_free(real_url);
	ms_free(from);
	return err;
}

/**
 * Initiates an outgoing call
 *
 * @ingroup call_control
 * @param lc the LinphoneCore object
 * @param url the destination of the call (sip address, or phone number).
 *
 * The application doesn't own a reference to the returned LinphoneCall object.
 * Use linphone_call_ref() to safely keep the LinphoneCall pointer valid within your application.
 *
 * @return a LinphoneCall object or NULL in case of failure
**/
LinphoneCall * linphone_core_invite(LinphoneCore *lc, const char *url){
	LinphoneCall *call;
	LinphoneCallParams *p=linphone_core_create_default_call_parameters (lc);
	call=linphone_core_invite_with_params(lc, url, p);
	linphone_call_params_destroy(p);
	return call;
}

/**
* Initiates an outgoing call
*
* @ingroup call_control
* @param lc the LinphoneCore object
* @param url the destination of the call (sip address, or phone number).
* @param offer the sdp string generated by webrtc
*
* The application doesn't own a reference to the returned LinphoneCall object.
* Use linphone_call_ref() to safely keep the LinphoneCall pointer valid within your application.
*
* @return a LinphoneCall object or NULL in case of failure
**/
LinphoneCall * linphone_core_invite_sdp(LinphoneCore *lc, const char *url, const char *offer) {
	if (url == NULL || offer == NULL)
	{
		return NULL;
	}

	LinphoneAddress *addr = linphone_core_interpret_url(lc, url);
	if (addr)
	{
		LinphoneCall *call;
		LinphoneCallParams *p = linphone_core_create_default_call_parameters(lc);
		call = linphone_core_invite_address_with_params(lc, addr, p, offer);
		linphone_call_params_destroy(p);
		linphone_address_destroy(addr);
		return call;
	}
	
	return NULL;
}

/**
 * Initiates an outgoing call according to supplied call parameters
 *
 * @ingroup call_control
 * @param lc the LinphoneCore object
 * @param url the destination of the call (sip address, or phone number).
 * @param p call parameters
 *
 * The application doesn't own a reference to the returned LinphoneCall object.
 * Use linphone_call_ref() to safely keep the LinphoneCall pointer valid within your application.
 *
 * @return a LinphoneCall object or NULL in case of failure
**/
LinphoneCall * linphone_core_invite_with_params(LinphoneCore *lc, const char *url, const LinphoneCallParams *p){
	LinphoneAddress *addr=linphone_core_interpret_url(lc,url);
	if (addr){
		LinphoneCall *call;
		call=linphone_core_invite_address_with_params(lc, addr, p, NULL);
		linphone_address_destroy(addr);
		return call;
	}
	return NULL;
}

/**
 * Initiates an outgoing call given a destination LinphoneAddress
 *
 * @ingroup call_control
 * @param lc the LinphoneCore object
 * @param addr the destination of the call (sip address).
 *
 * The LinphoneAddress can be constructed directly using linphone_address_new(), or
 * created by linphone_core_interpret_url().
 * The application doesn't own a reference to the returned LinphoneCall object.
 * Use linphone_call_ref() to safely keep the LinphoneCall pointer valid within your application.
 *
 * @return a LinphoneCall object or NULL in case of failure
**/
LinphoneCall * linphone_core_invite_address(LinphoneCore *lc, const LinphoneAddress *addr){
	LinphoneCall *call;
	LinphoneCallParams *p=linphone_core_create_default_call_parameters(lc);
	call=linphone_core_invite_address_with_params (lc,addr,p, NULL);
	linphone_call_params_destroy(p);
	return call;
}


/**
 * Initiates an outgoing call given a destination LinphoneAddress
 *
 * @ingroup call_control
 * @param lc the LinphoneCore object
 * @param addr the destination of the call (sip address).
 * @param params call parameters
 * @offer sdp for invite
 *
 * The LinphoneAddress can be constructed directly using linphone_address_new(), or
 * created by linphone_core_interpret_url().
 * The application doesn't own a reference to the returned LinphoneCall object.
 * Use linphone_call_ref() to safely keep the LinphoneCall pointer valid within your application.
 *
 * @return a LinphoneCall object or NULL in case of failure
**/
LinphoneCall * linphone_core_invite_address_with_params(LinphoneCore *lc, const LinphoneAddress *addr, const LinphoneCallParams *params, const char* offer)
{
	const char *route=NULL;
	const char *from=NULL;
	LinphoneProxyConfig *proxy=NULL,*dest_proxy=NULL;
	LinphoneAddress *parsed_url2=NULL;
	char *real_url=NULL;
	LinphoneCall *call;
	bool_t defer = FALSE;

	if(!linphone_core_can_we_add_call(lc)){
		if (lc->vtable.display_warning)
			lc->vtable.display_warning(lc,_("Sorry, we have reached the maximum number of simultaneous calls"));
		return NULL;
	}
	linphone_core_get_default_proxy(lc,&proxy);
	route=linphone_core_get_route(lc);

	real_url=linphone_address_as_string(addr);
	dest_proxy=linphone_core_lookup_known_proxy(lc, addr);

	if (proxy!=dest_proxy && dest_proxy!=NULL) {
		ms_message("Overriding default proxy setting for this call:");
		ms_message("The used identity will be %s",linphone_proxy_config_get_identity(dest_proxy));
	}

	if (dest_proxy!=NULL)
		from=linphone_proxy_config_get_identity(dest_proxy);
	else if (proxy!=NULL)
		from=linphone_proxy_config_get_identity(proxy);

	/* failed if no proxy or no identity defined for this proxy */
	if (from == NULL) 
		return NULL;

	parsed_url2 = linphone_address_new(from);

	call=linphone_call_new_outgoing(lc,parsed_url2,linphone_address_clone(addr),params);
	call->dest_proxy=dest_proxy;
	sal_op_set_route(call->op,route);

	if (offer != NULL)
	{
		call->local_sdp = ms_strdup(offer);
	}

	if(linphone_core_add_call(lc,call)!= 0)
	{
		ms_warning("we had a problem in adding the call into the invite ... weird");
		linphone_call_unref(call);
		return NULL;
	}
	/* this call becomes now the current one*/
	lc->current_call=call;
	linphone_call_set_state (call,LinphoneCallOutgoingInit,"Starting outgoing call");

	if (call->dest_proxy==NULL && lc->sip_conf.ping_with_options==TRUE){
		{
			/*defer the start of the call after the OPTIONS ping*/
			call->ping_replied=FALSE;
			call->ping_op=sal_op_new(lc->sal);
			sal_ping(call->ping_op,from,real_url);
			sal_op_set_user_pointer(call->ping_op,call);
			call->start_time=time(NULL);
			defer = TRUE;
		}
	}
	
	if (defer==FALSE) linphone_core_start_invite(lc,call);

	if (real_url!=NULL) ms_free(real_url);
	return call;
}

/**
 * Performs a simple call transfer to the specified destination.
 *
 * @ingroup call_control
 * The remote endpoint is expected to issue a new call to the specified destination.
 * The current call remains active and thus can be later paused or terminated.
**/
int linphone_core_transfer_call(LinphoneCore *lc, LinphoneCall *call, const char *url)
{
	char *real_url=NULL;
	LinphoneAddress *real_parsed_url=linphone_core_interpret_url(lc,url);

	if (!real_parsed_url){
		/* bad url */
		return -1;
	}
	if (call==NULL){
		ms_warning("No established call to refer.");
		return -1;
	}
	//lc->call=NULL; //Do not do that you will lose the call afterward . . .
	real_url=linphone_address_as_string (real_parsed_url);
	sal_call_refer(call->op,real_url);
	ms_free(real_url);
	linphone_address_destroy(real_parsed_url);
	linphone_call_set_transfer_state(call, LinphoneCallOutgoingInit);
	return 0;
}

/**
 * Transfer a call to destination of another running call. This is used for "attended transfer" scenarios.
 * @param lc linphone core object
 * @param call a running call you want to transfer
 * @param dest a running call whose remote person will receive the transfer
 * 
 * @ingroup call_control
 *
 * The transfered call is supposed to be in paused state, so that it is able to accept the transfer immediately.
 * The destination call is a call previously established to introduce the transfered person.
 * This method will send a transfer request to the transfered person. The phone of the transfered is then
 * expected to automatically call to the destination of the transfer. The receiver of the transfer will then automatically
 * close the call with us (the 'dest' call).
**/
int linphone_core_transfer_call_to_another(LinphoneCore *lc, LinphoneCall *call, LinphoneCall *dest){
	int result = sal_call_refer_with_replaces (call->op,dest->op);
	linphone_call_set_transfer_state(call, LinphoneCallOutgoingInit);
	return result;
}

bool_t linphone_core_inc_invite_pending(LinphoneCore*lc){
	LinphoneCall *call = linphone_core_get_current_call(lc);
	if(call != NULL)
	{
		if(call->dir==LinphoneCallIncoming
			&& (call->state == LinphoneCallIncomingReceived || call->state ==  LinphoneCallIncomingEarlyMedia))
			return TRUE;
	}
	return FALSE;
}

void linphone_core_notify_incoming_call(LinphoneCore *lc, LinphoneCall *call){
	char *barmesg;
	char *tmp;
	LinphoneAddress *from_parsed;
	//SalMediaDescription *md;
	bool_t propose_early_media = FALSE;

#if 0
	linphone_call_make_local_media_description(lc,call);
	sal_call_set_local_media_description(call->op,call->localdesc);
	md=sal_call_get_final_media_description(call->op);
	if (md){
		if (sal_media_description_empty(md)){
			sal_call_decline(call->op,SalReasonMedia,NULL);
			linphone_call_unref(call);
			return;
		}
	}
#endif

	from_parsed=linphone_address_new(sal_op_get_from(call->op));
	linphone_address_clean(from_parsed);
	tmp=linphone_address_as_string(from_parsed);
	linphone_address_destroy(from_parsed);
	barmesg=ortp_strdup_printf("%s %s%s",tmp,_("is contacting you"),
	    (sal_call_autoanswer_asked(call->op)) ?_(" and asked autoanswer."):_("."));
	if (lc->vtable.show) lc->vtable.show(lc);
	if (lc->vtable.display_status)
	    lc->vtable.display_status(lc,barmesg);

	linphone_call_set_state(call,LinphoneCallIncomingReceived,"Incoming call");

	if (call->state==LinphoneCallIncomingReceived){
		sal_call_notify_ringing(call->op, propose_early_media);

		if (propose_early_media){
			linphone_call_set_state(call,LinphoneCallIncomingEarlyMedia,"Incoming call early media");
		}
		bool_t auto_answer_replaceing_calls = FALSE;
		if (sal_call_get_replaces(call->op)!=NULL && auto_answer_replaceing_calls){
			linphone_core_accept_call(lc, call);
		}
	}
	linphone_call_unref(call);

	ms_free(barmesg);
	ms_free(tmp);
}

int linphone_core_start_update_call(LinphoneCore *lc, LinphoneCall *call){
	const char *subject;
	if (call->params.in_conference){
		subject="Conference";
	}else{
		subject="Media change";
	}
	if (lc->vtable.display_status)
		lc->vtable.display_status(lc,_("Modifying call parameters..."));
	return sal_call_update(call->op, subject);
}

/**
 * @ingroup call_control
 * Updates a running call according to supplied call parameters or parameters changed in the LinphoneCore.
 *
 * In this version this is limited to the following use cases:
 * - setting up/down the video stream according to the video parameter of the LinphoneCallParams (see linphone_call_params_enable_video() ).
 * - changing the size of the transmitted video after calling linphone_core_set_preferred_video_size()
 *
 * In case no changes are requested through the LinphoneCallParams argument, then this argument can be omitted and set to NULL.
 * @param lc the core
 * @param call the call to be updated
 * @param params the new call parameters to use. (may be NULL)
 * @return 0 if successful, -1 otherwise.
**/
int linphone_core_update_call(LinphoneCore *lc, LinphoneCall *call, const LinphoneCallParams *params){
	int err=0;

	if (params!=NULL){
		linphone_call_set_state(call,LinphoneCallUpdating,"Updating call");
		err = linphone_core_start_update_call(lc, call);
	}

	return err;
}

/**
 * @ingroup call_control
 * When receiving a #LinphoneCallUpdatedByRemote state notification, prevent LinphoneCore from performing an automatic answer.
 * 
 * When receiving a #LinphoneCallUpdatedByRemote state notification (ie an incoming reINVITE), the default behaviour of
 * LinphoneCore is to automatically answer the reINIVTE with call parameters unchanged.
 * However when for example when the remote party updated the call to propose a video stream, it can be useful
 * to prompt the user before answering. This can be achieved by calling linphone_core_defer_call_update() during 
 * the call state notifiacation, to deactivate the automatic answer that would just confirm the audio but reject the video.
 * Then, when the user responds to dialog prompt, it becomes possible to call linphone_core_accept_call_update() to answer
 * the reINVITE, with eventually video enabled in the LinphoneCallParams argument.
 * 
 * @return 0 if successful, -1 if the linphone_core_defer_call_update() was done outside a #LinphoneCallUpdatedByRemote notification, which is illegal.
**/
int linphone_core_defer_call_update(LinphoneCore *lc, LinphoneCall *call){
	if (call->state==LinphoneCallUpdatedByRemote){
		call->defer_update=TRUE;
		return 0;
	}
	ms_error("linphone_core_defer_call_update() not done in state LinphoneCallUpdatedByRemote");
	return -1;
}

int linphone_core_start_accept_call_update(LinphoneCore *lc, LinphoneCall *call){
	sal_call_accept(call->op);
	linphone_call_set_state(call,LinphoneCallStreamsRunning,"Connected (streams running)");
	return 0;
}

/**
 * @ingroup call_control
 * Accept call modifications initiated by other end.
 * 
 * This call may be performed in response to a #LinphoneCallUpdatedByRemote state notification.
 * When such notification arrives, the application can decide to call linphone_core_defer_update_call() so that it can
 * have the time to prompt the user. linphone_call_get_remote_params() can be used to get information about the call parameters
 * requested by the other party, such as whether a video stream is requested.
 * 
 * When the user accepts or refuse the change, linphone_core_accept_call_update() can be done to answer to the other party.
 * If params is NULL, then the same call parameters established before the update request will continue to be used (no change).
 * If params is not NULL, then the update will be accepted according to the parameters passed.
 * Typical example is when a user accepts to start video, then params should indicate that video stream should be used 
 * (see linphone_call_params_enable_video()).
 * @param lc the linphone core object.
 * @param call the LinphoneCall object
 * @param params a LinphoneCallParams object describing the call parameters to accept.
 * @return 0 if sucessful, -1 otherwise (actually when this function call is performed outside ot #LinphoneCallUpdatedByRemote state).
**/
int linphone_core_accept_call_update(LinphoneCore *lc, LinphoneCall *call, const LinphoneCallParams *params){
	SalMediaDescription *remote_desc;
	bool_t keep_sdp_version;

	if (call->state!=LinphoneCallUpdatedByRemote){
		ms_error("linphone_core_accept_update(): invalid state %s to call this function.",
		         linphone_call_state_to_string(call->state));
		return -1;
	}
	remote_desc = sal_call_get_remote_media_description(call->op);
	keep_sdp_version = TRUE;
	if (keep_sdp_version &&(remote_desc->session_id == call->remote_session_id) && (remote_desc->session_ver == call->remote_session_ver)) {
		/* Remote has sent an INVITE with the same SDP as before, so send a 200 OK with the same SDP as before. */
		ms_warning("SDP version has not changed, send same SDP as before.");
		sal_call_accept(call->op);
		linphone_call_set_state(call,LinphoneCallStreamsRunning,"Connected (streams running)");
		return 0;
	}
	
	call->params=*params;

	linphone_core_start_accept_call_update(lc, call);
	return 0;
}

/**
 * Accept an incoming call.
 *
 * @ingroup call_control
 * Basically the application is notified of incoming calls within the
 * call_state_changed callback of the #LinphoneCoreVTable structure, where it will receive
 * a LinphoneCallIncoming event with the associated LinphoneCall object.
 * The application can later accept the call using this method.
 * @param lc the LinphoneCore object
 * @param call the LinphoneCall object representing the call to be answered.
 *
**/
int linphone_core_accept_call(LinphoneCore *lc, LinphoneCall *call){
	return linphone_core_accept_call_with_params(lc,call,NULL);
}

/**
 * Accept an incoming call, with parameters.
 *
 * @ingroup call_control
 * Basically the application is notified of incoming calls within the
 * call_state_changed callback of the #LinphoneCoreVTable structure, where it will receive
 * a LinphoneCallIncoming event with the associated LinphoneCall object.
 * The application can later accept the call using
 * this method.
 * @param lc the LinphoneCore object
 * @param call the LinphoneCall object representing the call to be answered.
 * @param params the specific parameters for this call, for example whether video is accepted or not. Use NULL to use default parameters.
 *
**/
int linphone_core_accept_call_with_params(LinphoneCore *lc, LinphoneCall *call, const LinphoneCallParams *params)
{
	LinphoneProxyConfig *cfg=NULL;
	const char *contact=NULL;
	SalOp *replaced;
	//SalMediaDescription *new_md;
	bool_t was_ringing=FALSE;

	if (call==NULL){
		//if just one call is present answer the only one ...
		if(linphone_core_get_calls_nb (lc) != 1)
			return -1;
		else
			call = (LinphoneCall*)linphone_core_get_calls(lc)->data;
	}

	if (call->state==LinphoneCallConnected){
		/*call already accepted*/
		return -1;
	}

	/* check if this call is supposed to replace an already running one*/
	replaced=sal_call_get_replaces(call->op);
	if (replaced){
		LinphoneCall *rc=(LinphoneCall*)sal_op_get_user_pointer (replaced);
		if (rc){
			ms_message("Call %p replaces call %p. This last one is going to be terminated automatically.",
			           call,rc);
			linphone_core_terminate_call(lc,rc);
		}
	}
	
	linphone_core_get_default_proxy(lc,&cfg);
	call->dest_proxy = cfg;
	call->dest_proxy = linphone_core_lookup_known_proxy(lc,call->log->to);

	if (cfg!=call->dest_proxy && call->dest_proxy!=NULL) {
		ms_message("Overriding default proxy setting for this call:");
		ms_message("The used identity will be %s",linphone_proxy_config_get_identity(call->dest_proxy));
	}

	/*try to be best-effort in giving real local or routable contact address*/
	contact = get_fixed_contact(lc, call,call->dest_proxy);
	if (contact)
		sal_op_set_contact(call->op,contact);

	if (params){
		_linphone_call_params_copy(&call->params,params);
	}
	linphone_call_update_remote_session_id_and_ver(call);

	if (call->local_sdp != NULL)
	{
		sal_call_set_local_sdp(call->op, call->local_sdp);

		// need ?
		if (call->localdesc != NULL)
		{
			sal_media_description_unref(call->localdesc);
			call->localdesc = NULL;
		}
		call->localdesc = sal_media_description_new();
		sal_media_decription_new_from_str(call->local_sdp, call->localdesc);

		const char *me = linphone_core_get_identity(lc);
		LinphoneAddress *addr = linphone_address_new(me);
		const char *username = linphone_address_get_username(addr);
		strncpy(call->localdesc->addr, call->localip, sizeof(call->localdesc->addr));
		strncpy(call->localdesc->username, username, sizeof(call->localdesc->username));

		sal_call_set_local_media_description(call->op, call->localdesc);
	}
	sal_call_accept(call->op);

	if (lc->vtable.display_status!=NULL)
		lc->vtable.display_status(lc,_("Connected."));

	lc->current_call=call;
	linphone_call_set_state(call,LinphoneCallConnected,"Connected");

	linphone_call_set_state(call,LinphoneCallStreamsRunning,"Connected (streams running)");
	
	ms_message("call answered.");
	return 0;
}

int linphone_core_abort_call(LinphoneCore *lc, LinphoneCall *call, const char *error){
	sal_call_terminate(call->op);
	
	//linphone_call_stop_media_streams(call);
	
	if (lc->vtable.display_status!=NULL)
		lc->vtable.display_status(lc,_("Call aborted") );
	linphone_call_set_state(call,LinphoneCallError,error);
	return 0;
}

static void terminate_call(LinphoneCore *lc, LinphoneCall *call){
	if (call->state==LinphoneCallIncomingReceived){
		if (call->reason!=LinphoneReasonNotAnswered)
			call->reason=LinphoneReasonDeclined;
	}

	if (lc->vtable.display_status!=NULL)
		lc->vtable.display_status(lc,_("Call ended") );
	linphone_call_set_state(call,LinphoneCallEnd,"Call terminated");
}

int linphone_core_redirect_call(LinphoneCore *lc, LinphoneCall *call, const char *redirect_uri){
	if (call->state==LinphoneCallIncomingReceived){
		sal_call_decline(call->op,SalReasonRedirect,redirect_uri);
		call->reason=LinphoneReasonDeclined;
		terminate_call(lc,call);
	}else{
		ms_error("Bad state for call redirection.");
		return -1;
    }
	return 0;
}

/**
 * Terminates a call.
 *
 * @ingroup call_control
 * @param lc the LinphoneCore
 * @param the_call the LinphoneCall object representing the call to be terminated.
**/
int linphone_core_terminate_call(LinphoneCore *lc, LinphoneCall *the_call)
{
	LinphoneCall *call;
	if (the_call == NULL){
		call = linphone_core_get_current_call(lc);
		if (ms_list_size(lc->calls)==1){
			call=(LinphoneCall*)lc->calls->data;
		}else{
			ms_warning("No unique call to terminate !");
			return -1;
		}
	}
	else
	{
		call = the_call;
	}
	sal_call_terminate(call->op);
	terminate_call(lc,call);
	return 0;
}

/**
 * Decline a pending incoming call, with a reason.
 * 
 * @ingroup call_control
 * 
 * @param lc the linphone core
 * @param call the LinphoneCall, must be in the IncomingReceived state.
 * @param reason the reason for rejecting the call: LinphoneReasonDeclined or LinphoneReasonBusy
**/
int linphone_core_decline_call(LinphoneCore *lc, LinphoneCall * call, LinphoneReason reason){
	SalReason sal_reason=SalReasonUnknown;
	if (call->state!=LinphoneCallIncomingReceived && call->state!=LinphoneCallIncomingEarlyMedia){
		ms_error("linphone_core_decline_call(): Cannot decline a call that is in state %s",linphone_call_state_to_string(call->state));
		return -1;
	}
	switch(reason){
		case LinphoneReasonDeclined:
			sal_reason=SalReasonDeclined;
		break;
		case LinphoneReasonBusy:
			sal_reason=SalReasonBusy;
		break;
		default:
			ms_error("linphone_core_decline_call(): unsupported reason %s",linphone_reason_to_string(reason));
			return -1;
		break;
	}
	sal_call_decline(call->op,sal_reason,NULL);
	terminate_call(lc,call);
	return 0;
}

/**
 * Terminates all the calls.
 *
 * @ingroup call_control
 * @param lc The LinphoneCore
**/
int linphone_core_terminate_all_calls(LinphoneCore *lc){
	MSList *calls=lc->calls;
	while(calls) {
		LinphoneCall *c=(LinphoneCall*)calls->data;
		calls=calls->next;
		linphone_core_terminate_call(lc,c);
	}
	return 0;
}

/**
 * Returns the current list of calls.
 *
 * Note that this list is read-only and might be changed by the core after a function call to linphone_core_iterate().
 * Similarly the LinphoneCall objects inside it might be destroyed without prior notice.
 * To hold references to LinphoneCall object into your program, you must use linphone_call_ref().
 *
 * @ingroup call_control
**/
const MSList *linphone_core_get_calls(LinphoneCore *lc)
{
	return lc->calls;
}

/**
 * Returns TRUE if there is a call running.
 *
 * @ingroup call_control
**/
bool_t linphone_core_in_call(const LinphoneCore *lc){
	return linphone_core_get_current_call((LinphoneCore *)lc)!=NULL;
}

/**
 * Returns The _LinphoneCall struct of the current call if one is in call
 *
 * @ingroup call_control
**/
LinphoneCall *linphone_core_get_current_call(const LinphoneCore *lc){
	return lc->current_call;
}

/**
 * Pauses the call. If a music file has been setup using linphone_core_set_play_file(),
 * this file will be played to the remote user.
 *
 * @ingroup call_control
**/
int linphone_core_pause_call(LinphoneCore *lc, LinphoneCall *call){
	int err=_linphone_core_pause_call(lc,call);
	if (err==0)  call->paused_by_app=TRUE;
	return err;
}

/* Internal version that does not play tone indication*/
int _linphone_core_pause_call(LinphoneCore *lc, LinphoneCall *call)
{
	const char *subject=NULL;

	if (call->state!=LinphoneCallStreamsRunning && call->state!=LinphoneCallPausedByRemote){
		ms_warning("Cannot pause this call, it is not active.");
		return -1;
	}

#if 0
	linphone_call_make_local_media_description(lc,call);
	if (sal_media_description_has_dir(call->resultdesc,SalStreamSendRecv)){
		sal_media_description_set_dir(call->localdesc,SalStreamSendOnly);
		subject="Call on hold";
	}else if (sal_media_description_has_dir(call->resultdesc,SalStreamRecvOnly)){
		sal_media_description_set_dir(call->localdesc,SalStreamSendOnly);
		subject="Call on hold for me too";
	}else{
		ms_error("No reason to pause this call, it is already paused or inactive.");
		return -1;
	}
	sal_call_set_local_media_description(call->op,call->localdesc);
#endif

	if (sal_call_update(call->op,subject) != 0){
		if (lc->vtable.display_warning)
			lc->vtable.display_warning(lc,_("Could not pause the call"));
	}
	lc->current_call = NULL;

	linphone_call_set_state(call,LinphoneCallPausing,"Pausing call");
	if (lc->vtable.display_status)
		lc->vtable.display_status(lc,_("Pausing the current call..."));

	call->paused_by_app=FALSE;
	return 0;
}

/**
 * Pause all currently running calls.
 * @ingroup call_control
**/
int linphone_core_pause_all_calls(LinphoneCore *lc){
	const MSList *elem;
	for(elem=lc->calls;elem!=NULL;elem=elem->next){
		LinphoneCall *call=(LinphoneCall *)elem->data;
		LinphoneCallState cs=linphone_call_get_state(call);
		if (cs==LinphoneCallStreamsRunning || cs==LinphoneCallPausedByRemote){
			_linphone_core_pause_call(lc,call);
		}
	}
	return 0;
}

/**
 * Resumes the call.
 *
 * @ingroup call_control
**/
int linphone_core_resume_call(LinphoneCore *lc, LinphoneCall *the_call)
{
	char temp[255]={0};
	LinphoneCall *call = the_call;
	const char *subject="Call resuming";
	
	if(call->state!=LinphoneCallPaused ){
		ms_warning("we cannot resume a call that has not been established and paused before");
		return -1;
	}
	if (call->params.in_conference==FALSE){
		ms_message("Resuming call %p",call);
	}

#if 0
	linphone_call_make_local_media_description(lc,the_call);	
	sal_call_set_local_media_description(call->op,call->localdesc);
	sal_media_description_set_dir(call->localdesc,SalStreamSendRecv);
#endif

	if (call->params.in_conference && !call->current_params.in_conference) {
		subject = "Conference";
	}
	
	if(sal_call_update(call->op,subject) != 0){
		return -1;
	}
	
	linphone_call_set_state (call,LinphoneCallResuming,"Resuming");

	snprintf(temp,sizeof(temp)-1,"Resuming the call with %s",linphone_call_get_remote_address_as_string(call));
	if (lc->vtable.display_status)
		lc->vtable.display_status(lc,temp);
	return 0;
}

static int remote_address_compare(LinphoneCall *call, const LinphoneAddress *raddr){
	const LinphoneAddress *addr=linphone_call_get_remote_address (call);
	return !linphone_address_weak_equal (addr,raddr);
}

/**
 * Get the call with the remote_address specified
 * @param lc
 * @param remote_address
 * @return the LinphoneCall of the call if found
 * 
 * @ingroup call_control
 */
LinphoneCall *linphone_core_get_call_by_remote_address(LinphoneCore *lc, const char *remote_address){
	LinphoneAddress *raddr=linphone_address_new(remote_address);
	MSList *elem=ms_list_find_custom(lc->calls,(int (*)(const void*,const void *))remote_address_compare,raddr);
	if (elem) return (LinphoneCall*) elem->data;
	return NULL;
}

int linphone_core_send_publish(LinphoneCore *lc,
			       LinphoneOnlineStatus presence_mode)
{
	const MSList *elem;
	for (elem=linphone_core_get_proxy_config_list(lc);elem!=NULL;elem=ms_list_next(elem)){
		LinphoneProxyConfig *cfg=(LinphoneProxyConfig*)elem->data;
		if (cfg->publish) linphone_proxy_config_send_publish(cfg,presence_mode);
	}
	return 0;
}

/**
 * Set the incoming call timeout in seconds.
 *
 * @ingroup call_control
 * If an incoming call isn't answered for this timeout period, it is
 * automatically declined.
**/
void linphone_core_set_inc_timeout(LinphoneCore *lc, int seconds){
	lc->sip_conf.inc_timeout=seconds;
}

/**
 * Returns the incoming call timeout
 *
 * @ingroup call_control
 * See linphone_core_set_inc_timeout() for details.
**/
int linphone_core_get_inc_timeout(LinphoneCore *lc){
	return lc->sip_conf.inc_timeout;
}

/**
 * Set the in call timeout in seconds.
 *
 * @ingroup call_control
 * After this timeout period, the call is automatically hangup.
**/
void linphone_core_set_in_call_timeout(LinphoneCore *lc, int seconds){
	lc->sip_conf.in_call_timeout=seconds;
}

/**
 * Returns the in call timeout
 *
 * @ingroup call_control
 * See linphone_core_set_in_call_timeout() for details.
**/
int linphone_core_get_in_call_timeout(LinphoneCore *lc){
	return lc->sip_conf.in_call_timeout;
}

/**
 * Returns the delayed timeout
 *
 * @ingroup call_control
 * See linphone_core_set_delayed_timeout() for details.
**/
int linphone_core_get_delayed_timeout(LinphoneCore *lc){
	return lc->sip_conf.delayed_timeout;
}

/**
* Set the in delayed timeout in seconds.
*
* @ingroup call_control
* After this timeout period, a delayed call (internal call initialisation or resolution) is resumed.
**/
void linphone_core_set_delayed_timeout(LinphoneCore *lc, int seconds) {
	lc->sip_conf.delayed_timeout = seconds;
}

/**
 * Set the sip listen port to use random port or not
 */
int linphone_core_set_sip_random_port(LinphoneCore * lc, bool_t val)
{
	if (lc->sip_conf.sip_random_port != val)
	{
		lc->sip_conf.sip_random_port = val;
		int random_port = generate_random_port();
		random_port = random_port <= 0 ? 5060:random_port;

		LCSipTransports *tr = &lc->sip_conf.transports;
		if (tr->transport == LcTransportTCP)
		{
			tr->tcp_port = random_port;
		}
		else if (tr->transport == LcTransportTLS)
		{
			tr->tls_port = random_port;
		}
		else if (tr->transport == LcTransportDTLS)
		{
			tr->dtls_port = random_port;
		}
		else
		{
			tr->udp_port = random_port;
		}
		
		if (lc->sal == NULL) return 0;

		return apply_transports(lc);
	}

	return 0;
}

/**
 * Returns if use sip random port
 */
bool_t linphone_core_get_sip_random_port(LinphoneCore * lc)
{
	return lc->sip_conf.sip_random_port;
}

#if 0
void linphone_core_set_presence_info(LinphoneCore *lc,int minutes_away,
													const char *contact,
													LinphoneOnlineStatus presence_mode)
{
	if (minutes_away>0) lc->minutes_away=minutes_away;

	if (lc->alt_contact!=NULL) {
		ms_free(lc->alt_contact);
		lc->alt_contact=NULL;
	}
	if (contact) lc->alt_contact=ms_strdup(contact);
	if (lc->presence_mode!=presence_mode){
		
		/*
		   Improve the use of all LINPHONE_STATUS available.
		   !TODO Do not mix "presence status" with "answer status code"..
		   Use correct parameter to follow sip_if_match/sip_etag.
		 */
		linphone_core_send_publish(lc,presence_mode);
	}
	lc->presence_mode=presence_mode;
}

LinphoneOnlineStatus linphone_core_get_presence_info(const LinphoneCore *lc){
	return lc->presence_mode;
}
#endif

/**
 * Sets the path to a file or folder containing trusted root CAs (PEM format)
 *
 * @param path
 * @param lc The LinphoneCore object
 *
 * @ingroup initializing
**/
void linphone_core_set_root_ca(LinphoneCore *lc,const char *path){
	sal_set_root_ca(lc->sal, path);
}

/**
 * Gets the path to a file or folder containing the trusted root CAs (PEM format)
 *
 * @param lc The LinphoneCore object
 *
 * @ingroup initializing
**/
const char *linphone_core_get_root_ca(LinphoneCore *lc){
	return sal_get_root_ca(lc->sal);
}

/**
 * Specify whether the tls server certificate must be verified when connecting to a SIP/TLS server.
 * 
 * @ingroup initializing
**/
void linphone_core_verify_server_certificates(LinphoneCore *lc, bool_t yesno){
	sal_verify_server_certificates(lc->sal,yesno);
}

/**
 * Specify whether the tls server certificate common name must be verified when connecting to a SIP/TLS server.
 * @ingroup initializing
**/
void linphone_core_verify_server_cn(LinphoneCore *lc, bool_t yesno){
	sal_verify_server_cn(lc->sal,yesno);
}

/**
 * Send the specified dtmf.
 *
 * @ingroup media_parameters
 * This function only works during calls. The dtmf is automatically played to the user.
 * @param lc The LinphoneCore object
 * @param dtmf The dtmf name specified as a char, such as '0', '#' etc...
 *
**/
void linphone_core_send_dtmf(LinphoneCore *lc, char dtmf)
{
	LinphoneCall *call=linphone_core_get_current_call(lc);
	if (call==NULL){
		ms_warning("linphone_core_send_dtmf(): no active call");
		return;
	}
	
	/* Out of Band DTMF (use INFO method) */
	sal_call_send_dtmf(call->op,dtmf);
}

void linphone_core_set_stun_server(LinphoneCore *lc, const char *server){
	if (lc->net_conf.stun_server!=NULL)
		ms_free(lc->net_conf.stun_server);
	if (server)
		lc->net_conf.stun_server=ms_strdup(server);
	else lc->net_conf.stun_server=NULL;
}

const char * linphone_core_get_stun_server(const LinphoneCore *lc){
	return lc->net_conf.stun_server;
}

const char * linphone_core_get_relay_addr(const LinphoneCore *lc){
	return lc->net_conf.relay;
}

int linphone_core_set_relay_addr(LinphoneCore *lc, const char *addr){
	if (lc->net_conf.relay!=NULL){
		ms_free(lc->net_conf.relay);
		lc->net_conf.relay=NULL;
	}
	if (addr){
		lc->net_conf.relay=ms_strdup(addr);
	}
	return 0;
}

void linphone_core_set_nat_address(LinphoneCore *lc, const char *addr)
{
	if (lc->net_conf.nat_address!=NULL){
		ms_free(lc->net_conf.nat_address);
	}
	if (addr!=NULL) lc->net_conf.nat_address=ms_strdup(addr);
	else lc->net_conf.nat_address=NULL;
	if (lc->sip_conf.contact) update_primary_contact(lc);
}

const char *linphone_core_get_nat_address(const LinphoneCore *lc) {
	return lc->net_conf.nat_address;
}

const char *linphone_core_get_nat_address_resolved(LinphoneCore *lc)
{
	struct sockaddr_storage ss;
	socklen_t ss_len;
	int error;
	char ipstring [INET6_ADDRSTRLEN];

	if (lc->net_conf.nat_address==NULL) return NULL;
	
	if (parse_hostname_to_addr (lc->net_conf.nat_address, &ss, &ss_len)<0) {
		return lc->net_conf.nat_address;
	}

	error = getnameinfo((struct sockaddr *)&ss, ss_len,
		ipstring, sizeof(ipstring), NULL, 0, NI_NUMERICHOST);
	if (error) {
		return lc->net_conf.nat_address;
	}

	if (lc->net_conf.nat_address_ip!=NULL){
		ms_free(lc->net_conf.nat_address_ip);
	}
	lc->net_conf.nat_address_ip = ms_strdup (ipstring);
	return lc->net_conf.nat_address_ip;
}

void linphone_core_set_firewall_policy(LinphoneCore *lc, LinphoneFirewallPolicy pol){
	lc->net_conf.firewall_policy=pol;

	if (lc->sip_conf.contact) update_primary_contact(lc);
}

LinphoneFirewallPolicy linphone_core_get_firewall_policy(const LinphoneCore *lc){
	return lc->net_conf.firewall_policy;
}

/**
 * Get the list of call logs (past calls).
 *
 * @ingroup call_logs
**/
const MSList * linphone_core_get_call_logs(LinphoneCore *lc){
	return lc->call_logs;
}

/**
 * Erase the call log.
 *
 * @ingroup call_logs
**/
void linphone_core_clear_call_logs(LinphoneCore *lc){
	lc->missed_calls=0;
	ms_list_for_each(lc->call_logs,(void (*)(void*))linphone_call_log_destroy);
	lc->call_logs=ms_list_free(lc->call_logs);
}

/**
 * Returns number of missed calls.
 * Once checked, this counter can be reset with linphone_core_reset_missed_calls_count().
**/
int linphone_core_get_missed_calls_count(LinphoneCore *lc) {
	return lc->missed_calls;
}

/**
 * Resets the counter of missed calls.
**/
void linphone_core_reset_missed_calls_count(LinphoneCore *lc) {
	lc->missed_calls=0;
}

/**
 * Remove a specific call log from call history list.
 * This function destroys the call log object. It must not be accessed anymore by the application after calling this function.
 * @param lc the linphone core object
 * @param a LinphoneCallLog object.
**/
void linphone_core_remove_call_log(LinphoneCore *lc, LinphoneCallLog *cl){
	lc->call_logs = ms_list_remove(lc->call_logs, cl);
	linphone_call_log_destroy(cl);
}


/**
 * Retrieves the user pointer that was given to linphone_core_new()
 *
 * @ingroup initializing
**/
void *linphone_core_get_user_data(LinphoneCore *lc){
	return lc->data;
}


/**
 * Associate a user pointer to the linphone core.
 *
 * @ingroup initializing
**/
void linphone_core_set_user_data(LinphoneCore *lc, void *userdata){
	lc->data=userdata;
}

void net_config_uninit(LinphoneCore *lc)
{
	net_config_t *config=&lc->net_conf;

	if (config->stun_server!=NULL){
		ms_free(lc->net_conf.stun_server);
	}
	if (config->nat_address!=NULL){		
		ms_free(lc->net_conf.nat_address);
	}
	if (lc->net_conf.nat_address_ip !=NULL){
		ms_free(lc->net_conf.nat_address_ip);
	}
}

void sip_config_uninit(LinphoneCore *lc)
{
	MSList *elem;
	int i;
	sip_config_t *config=&lc->sip_conf;
	
	for(elem=config->proxies,i=0;elem!=NULL;elem=ms_list_next(elem),i++){
		LinphoneProxyConfig *cfg=(LinphoneProxyConfig*)(elem->data);
		linphone_proxy_config_edit(cfg);	/* to unregister */
	}

	for (i=0; i < 10; i++){
		sal_iterate(lc->sal);
#ifndef WIN32
		usleep(100000);
#else
		Sleep(50);
#endif
	}

	ms_list_for_each(config->proxies,(void (*)(void*)) linphone_proxy_config_destroy);
	ms_list_free(config->proxies);
	config->proxies=NULL;

	ms_list_for_each(lc->auth_info,(void (*)(void*))linphone_auth_info_destroy);
	ms_list_free(lc->auth_info);
	lc->auth_info=NULL;

	sal_uninit(lc->sal);
	lc->sal=NULL;

	if (config->guessed_contact)
		ms_free(config->guessed_contact);

	if (config->contact)
		ms_free(config->contact);

}

static void linphone_core_uninit(LinphoneCore *lc)
{
	linphone_core_free_hooks(lc);
	while(lc->calls)
	{
		LinphoneCall *the_call = lc->calls->data;
		linphone_core_terminate_call(lc,the_call);
		linphone_core_iterate(lc);
#ifdef WIN32
		Sleep(50);
#else
		usleep(50000);
#endif
	}

	linphone_core_set_state(lc,LinphoneGlobalShutdown,"Shutting down");

	/* save all config */
	net_config_uninit(lc);
	sip_config_uninit(lc);
	ms_list_for_each(lc->call_logs,(void (*)(void*))linphone_call_log_destroy);
	lc->call_logs=ms_list_free(lc->call_logs);
	
	ms_list_for_each(lc->last_recv_msg_ids,ms_free);
	lc->last_recv_msg_ids=ms_list_free(lc->last_recv_msg_ids);
	
	linphone_core_set_state(lc,LinphoneGlobalOff,"Off");
}

static void set_network_reachable(LinphoneCore* lc,bool_t isReachable, time_t curtime){
	ms_message("Network state is now [%s]",isReachable?"UP":"DOWN");
	// second get the list of available proxies
	const MSList *elem=linphone_core_get_proxy_config_list(lc);
	for(;elem!=NULL;elem=elem->next){
		LinphoneProxyConfig *cfg=(LinphoneProxyConfig*)elem->data;
		if (linphone_proxy_config_register_enabled(cfg) ) {
			if (!isReachable) {
				linphone_proxy_config_set_state(cfg, LinphoneRegistrationNone,"Registration impossible (network down)");
			}else{
				cfg->commit=TRUE;
			}
		}
	}
	lc->netup_time=curtime;
	lc->network_reachable=isReachable;
	
	if(!isReachable) {
		sal_reset_transports(lc->sal);
	}
}

void linphone_core_refresh_registers(LinphoneCore* lc) {
	const MSList *elem;
	if (!lc->network_reachable) {
		ms_warning("Refresh register operation not available (network unreachable)");
		return;
	}
	elem=linphone_core_get_proxy_config_list(lc);
	for(;elem!=NULL;elem=elem->next){
		LinphoneProxyConfig *cfg=(LinphoneProxyConfig*)elem->data;
		if (linphone_proxy_config_register_enabled(cfg) && linphone_proxy_config_get_expires(cfg)>0) {
			linphone_proxy_config_refresh_register(cfg);
		}
	}
}

void __linphone_core_invalidate_registers(LinphoneCore* lc){
	const MSList *elem=linphone_core_get_proxy_config_list(lc);
	for(;elem!=NULL;elem=elem->next){
		LinphoneProxyConfig *cfg=(LinphoneProxyConfig*)elem->data;
		if (linphone_proxy_config_register_enabled(cfg)) {
			linphone_proxy_config_edit(cfg);
			linphone_proxy_config_done(cfg);
		}
	}
}

void linphone_core_set_network_reachable(LinphoneCore* lc,bool_t isReachable) {
	//first disable automatic mode
	if (lc->auto_net_state_mon) {
		ms_message("Disabling automatic network state monitoring");
		lc->auto_net_state_mon=FALSE;
	}
	set_network_reachable(lc,isReachable, ms_time(NULL));
}

bool_t linphone_core_is_network_reachable(LinphoneCore* lc) {
	return lc->network_reachable;
}

/**
 * Destroys a LinphoneCore
 *
 * @ingroup initializing
**/
void linphone_core_destroy(LinphoneCore *lc){
	linphone_core_uninit(lc);
	ms_free(lc);
}

/**
 * Get the number of Call
 *
 * @ingroup call_control
**/
int linphone_core_get_calls_nb(const LinphoneCore *lc){
	return  ms_list_size(lc->calls);;
}

/**
 * Check if we do not have exceed the number of simultaneous call
 *
 * @ingroup call_control
**/
bool_t linphone_core_can_we_add_call(LinphoneCore *lc)
{
	if(linphone_core_get_calls_nb(lc) < lc->max_calls)
		return TRUE;
	ms_message("Maximum amount of simultaneous calls reached !");
	return FALSE;
}


int linphone_core_add_call( LinphoneCore *lc, LinphoneCall *call)
{
	if(linphone_core_can_we_add_call(lc))
	{
		lc->calls = ms_list_append(lc->calls,call);
		return 0;
	}
	return -1;
}

int linphone_core_del_call( LinphoneCore *lc, LinphoneCall *call)
{
	MSList *it;
	MSList *the_calls = lc->calls;

	it=ms_list_find(the_calls,call);
	if (it)
	{
		the_calls = ms_list_remove_link(the_calls,it);
	}
	else
	{
		ms_warning("could not find the call into the list\n");
		return -1;
	}
	lc->calls = the_calls;
	return 0;
}


const char *linphone_global_state_to_string(LinphoneGlobalState gs){
	switch(gs){
		case LinphoneGlobalOff:
			return "LinphoneGlobalOff";
		break;
		case LinphoneGlobalOn:
			return "LinphoneGlobalOn";
		break;
		case LinphoneGlobalStartup:
			return "LinphoneGlobalStartup";
		break;
		case LinphoneGlobalShutdown:
			return "LinphoneGlobalShutdown";
		break;
	}
	return NULL;
}

LinphoneGlobalState linphone_core_get_global_state(const LinphoneCore *lc){
	return lc->state;
}

LinphoneCallParams *linphone_core_create_default_call_parameters(LinphoneCore *lc){
	LinphoneCallParams *p=ms_new0(LinphoneCallParams,1);
	linphone_core_init_default_params(lc, p);
	return p;
}

const char *linphone_reason_to_string(LinphoneReason err){
	switch(err){
		case LinphoneReasonNone:
			return "No error";
		case LinphoneReasonNoResponse:
			return "No response";
		case LinphoneReasonBadCredentials:
			return "Bad credentials";
		case LinphoneReasonDeclined:
			return "Call declined";
		case LinphoneReasonNotFound:
			return "User not found";
		case LinphoneReasonNotAnswered:
			return "Not answered";
		case LinphoneReasonBusy:
			return "Busy";
	}
	return "unknown error";
}

const char *linphone_error_to_string(LinphoneReason err){
	return linphone_reason_to_string(err);
}
/**
 * Enables signaling keep alive
 */
void linphone_core_enable_keep_alive(LinphoneCore* lc,bool_t enable) {

	if (enable > 0) {
		sal_use_tcp_tls_keepalive(lc->sal,lc->sip_conf.tcp_tls_keepalive);
		sal_set_keepalive_period(lc->sal,lc->sip_conf.keepalive_period);
	} else {
		sal_set_keepalive_period(lc->sal,0);
	}
}

/**
 * Is signaling keep alive enabled
 */
bool_t linphone_core_keep_alive_enabled(LinphoneCore* lc) {
	return sal_get_keepalive_period(lc->sal) > 0;
}

int linphone_core_get_max_calls(LinphoneCore *lc) {
	return lc->max_calls;
}
void linphone_core_set_max_calls(LinphoneCore *lc, int max) {
	lc->max_calls=max;
}

typedef struct Hook{
	LinphoneCoreIterateHook fun;
	void *data;
}Hook;

static Hook *hook_new(LinphoneCoreIterateHook hook, void *hook_data){
	Hook *h=ms_new(Hook,1);
	h->fun=hook;
	h->data=hook_data;
	return h;
}

static void hook_invoke(Hook *h){
	h->fun(h->data);
}

void linphone_core_add_iterate_hook(LinphoneCore *lc, LinphoneCoreIterateHook hook, void *hook_data){
	lc->hooks=ms_list_append(lc->hooks,hook_new(hook,hook_data));
}

static void linphone_core_run_hooks(LinphoneCore *lc){
	ms_list_for_each(lc->hooks,(void (*)(void*))hook_invoke);
}

static void linphone_core_free_hooks(LinphoneCore *lc){
	ms_list_for_each(lc->hooks,(void (*)(void*))ms_free);
	ms_list_free(lc->hooks);
	lc->hooks=NULL;
}

void linphone_core_remove_iterate_hook(LinphoneCore *lc, LinphoneCoreIterateHook hook, void *hook_data){
	MSList *elem;
	for(elem=lc->hooks;elem!=NULL;elem=elem->next){
		Hook *h=(Hook*)elem->data;
		if (h->fun==hook && h->data==hook_data){
			lc->hooks = ms_list_remove_link(lc->hooks,elem);
			ms_free(h);
			return;
		}
	}
	ms_error("linphone_core_remove_iterate_hook(): No such hook found.");
}

const LinphoneCall* linphone_core_find_call_from_uri(LinphoneCore *lc, const char *uri) {
	if (uri == NULL) return NULL;
	MSList *calls=lc->calls;
	while(calls) {
		const LinphoneCall *c=(LinphoneCall*)calls->data;
		calls=calls->next;
		const LinphoneAddress *address = linphone_call_get_remote_address(c);
		char *current_uri=linphone_address_as_string_uri_only(address);
		if (strcmp(uri,current_uri)==0) {
			ms_free(current_uri);
			return c;
		} else {
			ms_free(current_uri);
		}
	}
	return NULL;
}

void linphone_core_init_default_params(LinphoneCore*lc, LinphoneCallParams *params) {
	params->in_conference=FALSE;
}

void linphone_core_set_device_identifier(LinphoneCore *lc,const char* device_id) {
	if (lc->device_id) ms_free(lc->device_id);
	lc->device_id=ms_strdup(device_id);
}
const char*  linphone_core_get_device_identifier(const LinphoneCore *lc) {
	return lc->device_id;
}

/**
 * Set the DSCP field for SIP signaling channel.
 * 
 * @ingroup network_parameters
 * * The DSCP defines the quality of service in IP packets.
 * 
**/
void linphone_core_set_sip_dscp(LinphoneCore *lc, int dscp){
	sal_set_dscp(lc->sal,dscp);
	if (linphone_core_ready(lc)){
		apply_transports(lc);
	}
}

/**
 * Get the DSCP field for SIP signaling channel.
 * 
 * @ingroup network_parameters
 * * The DSCP defines the quality of service in IP packets.
 * 
**/
int linphone_core_get_sip_dscp(const LinphoneCore *lc){	
	return sal_get_dscp(lc->sal);
}

