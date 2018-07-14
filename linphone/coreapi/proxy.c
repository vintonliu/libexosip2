/*
linphone
Copyright (C) 2000  Simon MORLAT (simon.morlat@linphone.org)
*/
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
 
#include "linphonecore.h"
#include "private.h"

#include <ctype.h>

static SalPresenceStatus linphone_online_status_to_sal(LinphoneOnlineStatus os) {
	switch (os) {
	case LinphoneStatusOffline:
		return SalPresenceOffline;
		break;
	case LinphoneStatusOnline:
		return SalPresenceOnline;
		break;
	case LinphoneStatusBusy:
		return SalPresenceBusy;
		break;
	case LinphoneStatusBeRightBack:
		return SalPresenceBerightback;
		break;
	case LinphoneStatusAway:
		return SalPresenceAway;
		break;
	case LinphoneStatusOnThePhone:
		return SalPresenceOnthephone;
		break;
	case LinphoneStatusOutToLunch:
		return SalPresenceOuttolunch;
		break;
	case LinphoneStatusDoNotDisturb:
		return SalPresenceDonotdisturb;
		break;
	case LinphoneStatusMoved:
		return SalPresenceMoved;
		break;
	case LinphoneStatusAltService:
		return SalPresenceAltService;
		break;
	case LinphoneStatusPending:
		return SalPresenceOffline;
		break;
	default:
		return SalPresenceOffline;
		break;
	}
	return SalPresenceOffline;
}

static void linphone_proxy_config_init(LinphoneCore* lc,LinphoneProxyConfig *obj){
	memset(obj,0,sizeof(LinphoneProxyConfig));
	obj->magic=linphone_proxy_config_magic;
	obj->expires = 3600;
}

/**
 * @addtogroup proxies
 * @{
**/

/**
 * @deprecated, use #linphone_core_create_proxy_config instead
 *Creates an empty proxy config.
**/
LinphoneProxyConfig *linphone_proxy_config_new() {
	return linphone_core_create_proxy_config(NULL);
}
LinphoneProxyConfig * linphone_core_create_proxy_config(LinphoneCore *lc) {
	LinphoneProxyConfig *obj=NULL;
	obj=ms_new(LinphoneProxyConfig,1);
	linphone_proxy_config_init(lc,obj);
	return obj;
}



/**
 * Destroys a proxy config.
 * 
 * @note: LinphoneProxyConfig that have been removed from LinphoneCore with
 * linphone_core_remove_proxy_config() must not be freed.
**/
void linphone_proxy_config_destroy(LinphoneProxyConfig *obj){
	if (obj->reg_proxy!=NULL) ms_free(obj->reg_proxy);
	if (obj->reg_identity!=NULL) ms_free(obj->reg_identity);
	if (obj->reg_route!=NULL) ms_free(obj->reg_route);	
	if (obj->realm!=NULL) ms_free(obj->realm);
	if (obj->type!=NULL) ms_free(obj->type);
	if (obj->dial_prefix!=NULL) ms_free(obj->dial_prefix);
	if (obj->op) sal_op_release(obj->op);
	if (obj->publish_op) sal_op_release(obj->publish_op);
}

/**
 * Returns a boolean indicating that the user is sucessfully registered on the proxy.
**/
bool_t linphone_proxy_config_is_registered(const LinphoneProxyConfig *obj){
	return obj->state == LinphoneRegistrationOk;
}

/**
 * Sets the proxy address
 *
 * Examples of valid sip proxy address are:
 * - IP address: sip:87.98.157.38
 * - IP address with port: sip:87.98.157.38:5062
 * - hostnames : sip:sip.example.net
**/
int linphone_proxy_config_set_server_addr(LinphoneProxyConfig *obj, const char *server_addr){
	LinphoneAddress *addr=NULL;
	char *modified=NULL;
	
	if (obj->reg_proxy!=NULL) ms_free(obj->reg_proxy);
	obj->reg_proxy=NULL;
	
	if (server_addr!=NULL && strlen(server_addr)>0){
		if (strstr(server_addr,"sip:")==NULL){
			modified=ms_strdup_printf("sip:%s",server_addr);
			addr=linphone_address_new(modified);
			ms_free(modified);
		}
		if (addr==NULL)
			addr=linphone_address_new(server_addr);
		if (addr){
			obj->reg_proxy=linphone_address_as_string(addr);
			linphone_address_destroy(addr);
		}else{
			ms_warning("Could not parse %s",server_addr);
			return -1;
		}
	}
	return 0;
}

/**
 * Sets the user identity as a SIP address.
 *
 * This identity is normally formed with display name, username and domain, such 
 * as:
 * Alice <sip:alice@example.net>
 * The REGISTER messages will have from and to set to this identity.
 *
**/
int linphone_proxy_config_set_identity(LinphoneProxyConfig *obj, const char *identity){
	LinphoneAddress *addr;
	if (identity!=NULL && strlen(identity)>0){
		addr=linphone_address_new(identity);
		if (!addr || linphone_address_get_username(addr)==NULL){
			ms_warning("Invalid sip identity: %s",identity);
			if (addr)
				linphone_address_destroy(addr);
			return -1;
		}else{
			if (obj->reg_identity!=NULL) {
				ms_free(obj->reg_identity);
				obj->reg_identity=NULL;
			}
			obj->reg_identity=ms_strdup(identity);
			if (obj->realm){
				ms_free(obj->realm);
			}
			obj->realm=ms_strdup(linphone_address_get_domain(addr));
			linphone_address_destroy(addr);
			return 0;
		}
	}
	return -1;
}

const char *linphone_proxy_config_get_domain(const LinphoneProxyConfig *cfg){
	return cfg->realm;
}

/**
 * Sets a SIP route.
 * When a route is set, all outgoing calls will go to the route's destination if this proxy
 * is the default one (see linphone_core_set_default_proxy() ).
**/
int linphone_proxy_config_set_route(LinphoneProxyConfig *obj, const char *route)
{
	if (obj->reg_route!=NULL){
		ms_free(obj->reg_route);
		obj->reg_route=NULL;
	}
	if (route!=NULL){
		SalAddress *addr;
		char *tmp;
		/*try to prepend 'sip:' */
		if (strstr(route,"sip:")==NULL){
			tmp=ms_strdup_printf("sip:%s",route);
		}else tmp=ms_strdup(route);
		addr=sal_address_new(tmp);
		if (addr!=NULL){
			sal_address_destroy(addr);
		}else{
			ms_free(tmp);
			tmp=NULL;
		}
		obj->reg_route=tmp;
	}
	return 0;
}

bool_t linphone_proxy_config_check(LinphoneCore *lc, LinphoneProxyConfig *obj){
	if (obj->reg_proxy==NULL){
		if (lc->vtable.display_warning)
			lc->vtable.display_warning(lc,_("The sip proxy address you entered is invalid, it must start with \"sip:\""
						" followed by a hostname."));
		return FALSE;
	}
	if (obj->reg_identity==NULL){
		if (lc->vtable.display_warning)
			lc->vtable.display_warning(lc,_("The sip identity you entered is invalid.\nIt should look like "
					"sip:username@proxydomain, such as sip:alice@example.net"));
		return FALSE;
	}
	return TRUE;
}

/**
 * Indicates whether a REGISTER request must be sent to the proxy.
**/
void linphone_proxy_config_enableregister(LinphoneProxyConfig *obj, bool_t val){
	obj->reg_sendregister=val;
}

/**
 * Sets the registration expiration time in seconds.
**/
void linphone_proxy_config_set_expires(LinphoneProxyConfig *obj, int val){
	if (val<0) val=600;
	obj->expires=val;
}

void linphone_proxy_config_enable_publish(LinphoneProxyConfig *obj, bool_t val){
	obj->publish=val;
}
/**
 * Starts editing a proxy configuration.
 *
 * Because proxy configuration must be consistent, applications MUST
 * call linphone_proxy_config_edit() before doing any attempts to modify
 * proxy configuration (such as identity, proxy address and so on).
 * Once the modifications are done, then the application must call
 * linphone_proxy_config_done() to commit the changes.
**/
void linphone_proxy_config_edit(LinphoneProxyConfig *obj){
	if (obj && obj->reg_sendregister){
		/* unregister */
		if (obj->state != LinphoneRegistrationNone && obj->state != LinphoneRegistrationCleared) {
			sal_unregister(obj->op);
		}
	}
}

void linphone_proxy_config_apply(LinphoneProxyConfig *obj,LinphoneCore *lc)
{
	obj->lc=lc;
	linphone_proxy_config_done(obj);
}

static char *guess_contact_for_register(LinphoneProxyConfig *obj){
	LinphoneAddress *proxy=linphone_address_new(obj->reg_proxy);
	char *ret=NULL;
	const char *host;
	if (proxy==NULL) return NULL;
	host=linphone_address_get_domain (proxy);
	if (host!=NULL){
		int localport = -1;
		char localip_tmp[LINPHONE_IPADDR_SIZE] = {'\0'};
		const char *localip = NULL;
		char *tmp;
		LCSipTransports tr;
		LinphoneAddress *contact;
		
		contact=linphone_address_new(obj->reg_identity);
		
		if(localip == NULL) {
			localip = localip_tmp;
			linphone_core_get_local_ip(obj->lc,host,localip_tmp);
		}
		if(localport == -1) {
			localport = linphone_core_get_sip_port(obj->lc);
		}
		linphone_address_set_port_int(contact,localport);
		linphone_address_set_domain(contact,localip);
		linphone_address_set_display_name(contact,NULL);
		
		linphone_core_get_sip_transports(obj->lc,&tr);
		if (tr.transport == LcTransportTCP)
		{
			sal_address_set_param(contact, "transport", "tcp");
		}
		else if (tr.transport == LcTransportTLS)
		{
			sal_address_set_param(contact, "transport", "tls");
		}

		tmp=linphone_address_as_string_uri_only(contact);
		if (obj->contact_params)
			ret=ms_strdup_printf("<%s;%s>",tmp,obj->contact_params);
		else ret=ms_strdup_printf("<%s>",tmp);
		linphone_address_destroy(contact);
		ms_free(tmp);
	}
	linphone_address_destroy (proxy);
	return ret;
}

static void linphone_proxy_config_register(LinphoneProxyConfig *obj){
	if (obj->reg_sendregister){
		char *contact;
		if (obj->op)
			sal_op_release(obj->op);
		obj->op=sal_op_new(obj->lc->sal);
		contact=guess_contact_for_register(obj);
		sal_op_set_contact(obj->op,contact);
		ms_free(contact);
		sal_op_set_user_pointer(obj->op,obj);
		if (sal_register(obj->op,obj->reg_proxy,obj->reg_identity,obj->expires)==0) {
			linphone_proxy_config_set_state(obj,LinphoneRegistrationProgress,"Registration in progress");
		} else {
			linphone_proxy_config_set_state(obj,LinphoneRegistrationFailed,"Registration failed");
		}
	}
}

/**
 * Refresh a proxy registration.
 * This is useful if for example you resuming from suspend, thus IP address may have changed.
**/
void linphone_proxy_config_refresh_register(LinphoneProxyConfig *obj){
	if (obj->reg_sendregister && obj->op){
		if (sal_register_refresh(obj->op,obj->expires) == 0) {
			linphone_proxy_config_set_state(obj,LinphoneRegistrationProgress, "Refresh registration");
		}
	}
}

/**
 * Commits modification made to the proxy configuration.
**/
int linphone_proxy_config_done(LinphoneProxyConfig *obj)
{
	if (!linphone_proxy_config_check(obj->lc,obj)) return -1;
	obj->commit=TRUE;
	return 0;
}

void linphone_proxy_config_set_realm(LinphoneProxyConfig *cfg, const char *realm)
{
	if (cfg->realm!=NULL) {
		ms_free(cfg->realm);
		cfg->realm=NULL;
	}
	if (realm!=NULL) cfg->realm=ms_strdup(realm);
}

int linphone_proxy_config_send_publish(LinphoneProxyConfig *proxy,
			       LinphoneOnlineStatus presence_mode){
	int err;
	SalOp *op=sal_op_new(proxy->lc->sal);
	sal_op_set_route(op,proxy->reg_proxy);
	err=sal_publish(op,linphone_proxy_config_get_identity(proxy),
	    linphone_proxy_config_get_identity(proxy), linphone_online_status_to_sal(presence_mode));
	if (proxy->publish_op!=NULL)
		sal_op_release(proxy->publish_op);
	proxy->publish_op=op;
	return err;
}

/**
 * Returns the route set for this proxy configuration.
**/
const char *linphone_proxy_config_get_route(const LinphoneProxyConfig *obj){
	return obj->reg_route;
}

/**
 * Returns the SIP identity that belongs to this proxy configuration.
 *
 * The SIP identity is a SIP address (Display Name <sip:username@@domain> )
**/
const char *linphone_proxy_config_get_identity(const LinphoneProxyConfig *obj){
	return obj->reg_identity;
}

/**
 * Returns TRUE if PUBLISH request is enabled for this proxy.
**/
bool_t linphone_proxy_config_publish_enabled(const LinphoneProxyConfig *obj){
	return obj->publish;
}

/**
 * Returns the proxy's SIP address.
**/
const char *linphone_proxy_config_get_addr(const LinphoneProxyConfig *obj){
	return obj->reg_proxy;
}

/**
 * Returns the duration of registration.
**/
int linphone_proxy_config_get_expires(const LinphoneProxyConfig *obj){
	return obj->expires;
}

/**
 * Returns TRUE if registration to the proxy is enabled.
**/
bool_t linphone_proxy_config_register_enabled(const LinphoneProxyConfig *obj){
	return obj->reg_sendregister;
}

/**
 * Set optional contact parameters that will be added to the contact information sent in the registration.
 * @param obj the proxy config object
 * @param contact_params a string contaning the additional parameters in text form, like "myparam=something;myparam2=something_else"
 *
 * The main use case for this function is provide the proxy additional information regarding the user agent, like for example unique identifier or apple push id.
 * As an example, the contact address in the SIP register sent will look like <sip:joe@15.128.128.93:50421;apple-push-id=43143-DFE23F-2323-FA2232>.
**/
void linphone_proxy_config_set_contact_parameters(LinphoneProxyConfig *obj, const char *contact_params){
	if (obj->contact_params) {
		ms_free(obj->contact_params);
		obj->contact_params=NULL;
	}
	if (contact_params){
		obj->contact_params=ms_strdup(contact_params);
	}
}

/**
 * Returns previously set contact parameters.
**/
const char *linphone_proxy_config_get_contact_parameters(const LinphoneProxyConfig *obj){
	return obj->contact_params;
}

struct _LinphoneCore * linphone_proxy_config_get_core(const LinphoneProxyConfig *obj){
	return obj->lc;
}

/**
 * Add a proxy configuration.
 * This will start registration on the proxy, if registration is enabled.
**/
int linphone_core_add_proxy_config(LinphoneCore *lc, LinphoneProxyConfig *cfg){
	if (!linphone_proxy_config_check(lc,cfg)) {
		return -1;
	}
	if (ms_list_find(lc->sip_conf.proxies,cfg)!=NULL){
		ms_warning("ProxyConfig already entered, ignored.");
		return 0;
	}
	lc->sip_conf.proxies=ms_list_append(lc->sip_conf.proxies,(void *)cfg);
	linphone_proxy_config_apply(cfg,lc);
	return 0;
}

/**
 * Removes a proxy configuration.
 *
 * LinphoneCore will then automatically unregister and place the proxy configuration
 * on a deleted list. For that reason, a removed proxy does NOT need to be freed.
**/
void linphone_core_remove_proxy_config(LinphoneCore *lc, LinphoneProxyConfig *cfg){
	/* check this proxy config is in the list before doing more*/
	if (ms_list_find(lc->sip_conf.proxies,cfg)==NULL){
		ms_error("linphone_core_remove_proxy_config: LinphoneProxyConfig %p is not known by LinphoneCore (programming error?)",cfg);
		return;
	}
	lc->sip_conf.proxies=ms_list_remove(lc->sip_conf.proxies,(void *)cfg);
	/* add to the list of destroyed proxies, so that the possible unREGISTER request can succeed authentication */
	lc->sip_conf.deleted_proxies=ms_list_append(lc->sip_conf.deleted_proxies,(void *)cfg);
	cfg->deletion_date=ms_time(NULL);
	if (cfg->state==LinphoneRegistrationOk){
		/* this will unREGISTER */
		linphone_proxy_config_edit(cfg);
	}
	if (lc->default_proxy==cfg){
		lc->default_proxy=NULL;
	}
}

/**
 * Erase all proxies from config.
 *
 * @ingroup proxy
**/
void linphone_core_clear_proxy_config(LinphoneCore *lc){
	MSList* list=ms_list_copy(linphone_core_get_proxy_config_list((const LinphoneCore*)lc));
	MSList* copy=list;
	for(;list!=NULL;list=list->next){
		linphone_core_remove_proxy_config(lc,(LinphoneProxyConfig *)list->data);
	}
	ms_list_free(copy);
}
/**
 * Sets the default proxy.
 *
 * This default proxy must be part of the list of already entered LinphoneProxyConfig.
 * Toggling it as default will make LinphoneCore use the identity associated with
 * the proxy configuration in all incoming and outgoing calls.
**/
void linphone_core_set_default_proxy(LinphoneCore *lc, LinphoneProxyConfig *config){
	/* check if this proxy is in our list */
	if (config!=NULL){
		if (ms_list_find(lc->sip_conf.proxies,config)==NULL){
			ms_warning("Bad proxy address: it is not in the list !");
			lc->default_proxy=NULL;
			return ;
		}
	}
	lc->default_proxy=config;
}	

void linphone_core_set_default_proxy_index(LinphoneCore *lc, int index){
	if (index<0) linphone_core_set_default_proxy(lc,NULL);
	else linphone_core_set_default_proxy(lc,ms_list_nth_data(lc->sip_conf.proxies,index));
}

/**
 * Returns the default proxy configuration, that is the one used to determine the current identity.
**/
int linphone_core_get_default_proxy(LinphoneCore *lc, LinphoneProxyConfig **config){
	int pos=-1;
	if (config!=NULL) *config=lc->default_proxy;
	if (lc->default_proxy!=NULL){
		pos=ms_list_position(lc->sip_conf.proxies,ms_list_find(lc->sip_conf.proxies,(void *)lc->default_proxy));
	}
	return pos;
}

/**
 * Returns an unmodifiable list of entered proxy configurations.
**/
const MSList *linphone_core_get_proxy_config_list(const LinphoneCore *lc){
	return lc->sip_conf.proxies;
}


static bool_t can_register(LinphoneProxyConfig *cfg){
	LinphoneCore *lc=cfg->lc;

	if (lc->sip_conf.register_only_when_network_is_up){
			return lc->network_reachable;
	}
	return TRUE;
}

void linphone_proxy_config_update(LinphoneProxyConfig *cfg){
	LinphoneCore *lc=cfg->lc;
	if (cfg->commit){
		if (can_register(cfg)){
			linphone_proxy_config_register(cfg);
			if (cfg->publish && cfg->publish_op==NULL){
				linphone_proxy_config_send_publish(cfg,lc->presence_mode);
			}
			cfg->commit=FALSE;
		}
	}
}

void linphone_proxy_config_set_sip_setup(LinphoneProxyConfig *cfg, const char *type){
	if (cfg->type)
		ms_free(cfg->type);
	cfg->type=ms_strdup(type);
	if (linphone_proxy_config_get_addr(cfg)==NULL){
		/*put a placeholder so that the sip setup gets saved into the config */
		linphone_proxy_config_set_server_addr(cfg,"sip:undefined");
	}
}

void linphone_proxy_config_set_user_data(LinphoneProxyConfig *cr, void * ud) {
	cr->user_data=ud;
}

void * linphone_proxy_config_get_user_data(LinphoneProxyConfig *cr) {
	return cr->user_data;
}

void linphone_proxy_config_set_state(LinphoneProxyConfig *cfg, LinphoneRegistrationState state, const char *message){
	LinphoneCore *lc=cfg->lc;
	cfg->state=state;
	if (lc && lc->vtable.registration_state_changed){
		lc->vtable.registration_state_changed(lc,cfg,state,message);
	}
}

LinphoneRegistrationState linphone_proxy_config_get_state(const LinphoneProxyConfig *cfg){
	return cfg->state;
}

 const char *linphone_registration_state_to_string(LinphoneRegistrationState cs){
	 switch(cs){
		case LinphoneRegistrationCleared:
			 return "LinphoneRegistrationCleared";
		break;
		case LinphoneRegistrationNone:
			 return "LinphoneRegistrationNone";
		break;
		case LinphoneRegistrationProgress:
			return "LinphoneRegistrationProgress";
		break;
		case LinphoneRegistrationOk:
			 return "LinphoneRegistrationOk";
		break;
		case LinphoneRegistrationFailed:
			 return "LinphoneRegistrationFailed";
		break;
	 }
	 return NULL;
 }

LinphoneReason linphone_proxy_config_get_error(const LinphoneProxyConfig *cfg) {
	return cfg->error;
}

void linphone_proxy_config_set_error(LinphoneProxyConfig *cfg,LinphoneReason error) {
	cfg->error = error;
}


