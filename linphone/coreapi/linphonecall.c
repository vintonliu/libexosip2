
/*
linphone
Copyright (C) 2010  Belledonne Communications SARL
 (simon.morlat@linphone.org)

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
#ifdef WIN32
#include <time.h>
#endif
#include "linphonecore.h"
#include "private.h"
#include <math.h>

LinphoneCore *linphone_call_get_core(const LinphoneCall *call){
	return call->core;
}

const char* linphone_call_get_authentication_token(LinphoneCall *call){
	return call->auth_token;
}

bool_t linphone_call_get_authentication_token_verified(LinphoneCall *call){
	return call->auth_token_verified;
}

void linphone_call_make_local_media_description(LinphoneCore *lc, LinphoneCall *call){
	MSList *l = NULL;
	PayloadType *pt = NULL;
	SalMediaDescription *old_md=call->localdesc;
	int i;
	const char *me=linphone_core_get_identity(lc);
	LinphoneAddress *addr=linphone_address_new(me);
	const char *username=linphone_address_get_username (addr);
	SalMediaDescription *md=sal_media_description_new();
	bool_t keep_srtp_keys= FALSE;

	md->session_id=(old_md ? old_md->session_id : (rand() & 0xfff));
	md->session_ver=(old_md ? (old_md->session_ver+1) : (rand() & 0xfff));
	md->n_total_streams=(old_md ? old_md->n_total_streams : 1);
	md->n_active_streams=1;
	strncpy(md->addr,call->localip,sizeof(md->addr));
	strncpy(md->username,username,sizeof(md->username));
	
	/*set audio capabilities */
	strncpy(md->streams[0].rtp_addr,call->localip,sizeof(md->streams[0].rtp_addr));
	strncpy(md->streams[0].rtcp_addr,call->localip,sizeof(md->streams[0].rtcp_addr));
	md->streams[0].rtp_port=call->audio_port;
	md->streams[0].rtcp_port=call->audio_port+1;
	md->streams[0].type=SalAudio;
	//l=ms_list_append(l,pt);
	md->streams[0].payloads=l;

	if (call->params.has_video){
		md->n_active_streams++;
		md->streams[1].rtp_port=call->video_port;
		md->streams[1].rtcp_port=call->video_port+1;
		md->streams[1].proto=md->streams[0].proto;
		md->streams[1].type=SalVideo;
		md->streams[1].payloads=l;
	}
	if (md->n_total_streams < md->n_active_streams)
		md->n_total_streams = md->n_active_streams;

	/* Deactivate inactive streams. */
	for (i = md->n_active_streams; i < md->n_total_streams; i++) {
		md->streams[i].rtp_port = 0;
		md->streams[i].rtcp_port = 0;
		md->streams[i].proto = SalProtoRtpAvp;
		md->streams[i].type = (old_md ? old_md->streams[i].type : SalOther);
		md->streams[i].dir = SalStreamInactive;
		md->streams[i].payloads = l;
	}

	linphone_address_destroy(addr);
	call->localdesc=md;
	if (old_md) sal_media_description_unref(old_md);
}

static void linphone_call_init_common(LinphoneCall *call, LinphoneAddress *from, LinphoneAddress *to){
	call->magic=linphone_call_magic;
	call->refcnt=1;
	call->state=LinphoneCallIdle;
	call->transfer_state = LinphoneCallIdle;
	call->start_time=time(NULL);
	call->media_start_time=0;
	call->log=linphone_call_log_new(call, from, to);
	call->owns_call_log=TRUE;
}

LinphoneCall * linphone_call_new_outgoing(struct _LinphoneCore *lc, LinphoneAddress *from, LinphoneAddress *to, const LinphoneCallParams *params)
{
	LinphoneCall *call=ms_new0(LinphoneCall,1);
	call->dir=LinphoneCallOutgoing;
	call->op=sal_op_new(lc->sal);
	sal_op_set_user_pointer(call->op,call);
	call->core=lc;
	linphone_core_get_local_ip(lc,NULL,call->localip);
	linphone_call_init_common(call,from,to);
	_linphone_call_params_copy(&call->params,params);
	sal_op_set_custom_header(call->op,call->params.custom_headers);
	call->params.custom_headers=NULL;
	
	if (params->referer){
		sal_call_set_referer(call->op,params->referer->op);
		call->referer=linphone_call_ref(params->referer);
	}
	return call;
}

LinphoneCall * linphone_call_new_incoming(struct _LinphoneCore *lc, LinphoneAddress *from, LinphoneAddress *to, SalOp *op){
	LinphoneCall *call=ms_new0(LinphoneCall,1);
	char *from_str;
	const SalMediaDescription *md;

	call->dir=LinphoneCallIncoming;
	sal_op_set_user_pointer(op,call);
	call->op=op;
	call->core=lc;

	if (lc->sip_conf.ping_with_options){
		{
			/*the following sends an option request back to the caller so that
			 we get a chance to discover our nat'd address before answering.*/
			call->ping_op=sal_op_new(lc->sal);
			from_str=linphone_address_as_string_uri_only(from);
			sal_op_set_route(call->ping_op,sal_op_get_network_origin(op));
			sal_op_set_user_pointer(call->ping_op,call);
			sal_ping(call->ping_op,linphone_core_find_best_identity(lc,from,NULL),from_str);
			ms_free(from_str);
		}
	}

	linphone_address_clean(from);
	linphone_core_get_local_ip(lc,NULL,call->localip);
	linphone_call_init_common(call, from, to);
	call->log->call_id=ms_strdup(sal_op_get_call_id(op)); /*must be known at that time*/
	linphone_core_init_default_params(lc, &call->params);

	// sdp
	md=sal_call_get_remote_media_description(op);
	if (md) {
		// It is licit to receive an INVITE without SDP
		// In this case WE chose the media parameters according to policy.
		call->params.has_video &= linphone_core_media_description_contains_video_stream(md);
	}	
	// add by vinton
	call->remote_sdp = sal_call_get_remote_sdp_str(op);

	return call;
}

/* this function is called internally to get rid of a call.
 It performs the following tasks:
 - remove the call from the internal list of calls
 - update the call logs accordingly
*/

static void linphone_call_set_terminated(LinphoneCall *call){
	LinphoneCore *lc=call->core;

	call->owns_call_log=FALSE;
	linphone_call_log_completed(call);

	if (call == lc->current_call){
		ms_message("Resetting the current call");
		lc->current_call=NULL;
	}

	if (linphone_core_del_call(lc,call) != 0){
		ms_error("Could not remove the call from the list !!!");
	}

	if (call->referer){
		linphone_call_unref(call->referer);
		call->referer=NULL;
	}
}

void linphone_call_fix_call_parameters(LinphoneCall *call){
	call->params.has_video=call->current_params.has_video;
}

const char *linphone_call_state_to_string(LinphoneCallState cs){
	switch (cs){
		case LinphoneCallIdle:
			return "LinphoneCallIdle";
		case LinphoneCallIncomingReceived:
			return "LinphoneCallIncomingReceived";
		case LinphoneCallOutgoingInit:
			return "LinphoneCallOutgoingInit";
		case LinphoneCallOutgoingProgress:
			return "LinphoneCallOutgoingProgress";
		case LinphoneCallOutgoingRinging:
			return "LinphoneCallOutgoingRinging";
		case LinphoneCallOutgoingEarlyMedia:
			return "LinphoneCallOutgoingEarlyMedia";
		case LinphoneCallConnected:
			return "LinphoneCallConnected";
		case LinphoneCallStreamsRunning:
			return "LinphoneCallStreamsRunning";
		case LinphoneCallPausing:
			return "LinphoneCallPausing";
		case LinphoneCallPaused:
			return "LinphoneCallPaused";
		case LinphoneCallResuming:
			return "LinphoneCallResuming";
		case LinphoneCallRefered:
			return "LinphoneCallRefered";
		case LinphoneCallError:
			return "LinphoneCallError";
		case LinphoneCallEnd:
			return "LinphoneCallEnd";
		case LinphoneCallPausedByRemote:
			return "LinphoneCallPausedByRemote";
		case LinphoneCallUpdatedByRemote:
			return "LinphoneCallUpdatedByRemote";
		case LinphoneCallIncomingEarlyMedia:
			return "LinphoneCallIncomingEarlyMedia";
		case LinphoneCallUpdating:
			return "LinphoneCallUpdating";
		case LinphoneCallReleased:
			return "LinphoneCallReleased";
	}
	return "undefined state";
}

void linphone_call_set_state(LinphoneCall *call, LinphoneCallState cstate, const char *message){
	LinphoneCore *lc=call->core;

	if (call->state!=cstate){
		if (call->state==LinphoneCallEnd || call->state==LinphoneCallError){
			if (cstate!=LinphoneCallReleased){
				ms_warning("Spurious call state change from %s to %s, ignored.",linphone_call_state_to_string(call->state),
				   linphone_call_state_to_string(cstate));
				return;
			}
		}
		ms_message("Call %p: moving from state %s to %s",call,linphone_call_state_to_string(call->state),
		           linphone_call_state_to_string(cstate));
		if (cstate!=LinphoneCallRefered){
			/*LinphoneCallRefered is rather an event, not a state.
			 Indeed it does not change the state of the call (still paused or running)*/
			call->state=cstate;
		}
		if (cstate==LinphoneCallEnd || cstate==LinphoneCallError){
			switch(call->reason){
				case LinphoneReasonDeclined:
					call->log->status=LinphoneCallDeclined;
					break;
				case LinphoneReasonNotAnswered:
					call->log->status=LinphoneCallMissed;
				break;
				default:
				break;
			}
			linphone_call_set_terminated (call);
		}
		if (cstate == LinphoneCallConnected) {
			call->log->status=LinphoneCallSuccess;
			call->media_start_time=time(NULL);
		}

		if (lc->vtable.call_state_changed)
			lc->vtable.call_state_changed(lc,call,cstate,message);
		if (cstate==LinphoneCallReleased){
			if (call->op!=NULL) {
				/* so that we cannot have anymore upcalls for SAL
				 concerning this call*/
				sal_op_release(call->op);
				call->op=NULL;
			}
			linphone_call_unref(call);
		}
	}
}

static void linphone_call_destroy(LinphoneCall *obj)
{
	if (obj->op!=NULL) {
		sal_op_release(obj->op);
		obj->op=NULL;
	}
	if (obj->resultdesc!=NULL) {
		sal_media_description_unref(obj->resultdesc);
		obj->resultdesc=NULL;
	}
	if (obj->localdesc!=NULL) {
		sal_media_description_unref(obj->localdesc);
		obj->localdesc=NULL;
	}
	if (obj->ping_op) {
		sal_op_release(obj->ping_op);
	}
	if (obj->refer_to){
		ms_free(obj->refer_to);
	}
	if (obj->owns_call_log)
		linphone_call_log_destroy(obj->log);
	if (obj->auth_token) {
		ms_free(obj->auth_token);
	}
	if (obj->local_sdp != NULL)
	{
		ms_free(obj->local_sdp);
		obj->local_sdp = NULL;
	}

	linphone_call_params_uninit(&obj->params);
	ms_free(obj);
}

/**
 * @addtogroup call_control
 * @{
**/

/**
 * Increments the call 's reference count.
 * An application that wishes to retain a pointer to call object
 * must use this function to unsure the pointer remains
 * valid. Once the application no more needs this pointer,
 * it must call linphone_call_unref().
**/
LinphoneCall * linphone_call_ref(LinphoneCall *obj){
	obj->refcnt++;
	return obj;
}

/**
 * Decrements the call object reference count.
 * See linphone_call_ref().
**/
void linphone_call_unref(LinphoneCall *obj){
	obj->refcnt--;
	if (obj->refcnt==0){
		linphone_call_destroy(obj);
	}
}

/**
 * Returns current parameters associated to the call.
**/
const LinphoneCallParams * linphone_call_get_current_params(LinphoneCall *call){
	return &call->current_params;
}

static bool_t is_video_active(const SalStreamDescription *sd){
	return sd->rtp_port!=0 && sd->dir!=SalStreamInactive;
}

/**
 * Returns call parameters proposed by remote.
 * 
 * This is useful when receiving an incoming call, to know whether the remote party
 * supports video, encryption or whatever.
**/
const LinphoneCallParams * linphone_call_get_remote_params(LinphoneCall *call){
	LinphoneCallParams *cp=&call->remote_params;
	memset(cp,0,sizeof(*cp));
	if (call->op){
		SalMediaDescription *md=sal_call_get_remote_media_description(call->op);
		if (md){
			cp->custom_headers=(SalCustomHeader*)sal_op_get_custom_header(call->op);
			return cp;
		}
	}
	return NULL;
}

/**
 * Returns the remote address associated to this call
 *
**/
const LinphoneAddress * linphone_call_get_remote_address(const LinphoneCall *call){
	return call->dir==LinphoneCallIncoming ? call->log->from : call->log->to;
}

/**
 * Returns the remote address associated to this call as a string.
 *
 * The result string must be freed by user using ms_free().
**/
char *linphone_call_get_remote_address_as_string(const LinphoneCall *call){
	return linphone_address_as_string(linphone_call_get_remote_address(call));
}

/**
 * Retrieves the call's remote sdp
 */
char *linphone_call_get_remote_sdp_str(const LinphoneCall *call) {
	return call->remote_sdp;
}

/**
 * Set local sdp
 */
void linphone_call_set_local_sdp_str(LinphoneCall *call, const char* sdp) {
	if (sdp == NULL)
	{
		return;
	}
	if (call->local_sdp != NULL)
	{
		ms_free(call->local_sdp);
		call->local_sdp = NULL;
	}

	call->local_sdp = ms_strdup(sdp);
}

/**
 * Retrieves the call's current state.
**/
LinphoneCallState linphone_call_get_state(const LinphoneCall *call){
	return call->state;
}

/**
 * Returns the reason for a call termination (either error or normal termination)
**/
LinphoneReason linphone_call_get_reason(const LinphoneCall *call){
	return call->reason;
}

/**
 * Get the user_pointer in the LinphoneCall
 *
 * @ingroup call_control
 *
 * return user_pointer an opaque user pointer that can be retrieved at any time
**/
void *linphone_call_get_user_pointer(LinphoneCall *call)
{
	return call->user_pointer;
}

/**
 * Set the user_pointer in the LinphoneCall
 *
 * @ingroup call_control
 *
 * the user_pointer is an opaque user pointer that can be retrieved at any time in the LinphoneCall
**/
void linphone_call_set_user_pointer(LinphoneCall *call, void *user_pointer)
{
	call->user_pointer = user_pointer;
}

/**
 * Returns the call log associated to this call.
**/
LinphoneCallLog *linphone_call_get_call_log(const LinphoneCall *call){
	return call->log;
}

/**
 * Returns the refer-to uri (if the call was transfered).
**/
const char *linphone_call_get_refer_to(const LinphoneCall *call){
	return call->refer_to;
}

/**
 * Returns direction of the call (incoming or outgoing).
**/
LinphoneCallDir linphone_call_get_dir(const LinphoneCall *call){
	return call->log->dir;
}

/**
 * Returns the far end's user agent description string, if available.
**/
const char *linphone_call_get_remote_user_agent(LinphoneCall *call){
	if (call->op){
		return sal_op_get_remote_ua (call->op);
	}
	return NULL;
}

/**
 * Returns the far end's sip contact as a string, if available.
**/
const char *linphone_call_get_remote_contact(LinphoneCall *call){
	if (call->op){
		return sal_op_get_remote_contact(call->op);
	}
	return NULL;
}

/**
 * Returns true if this calls has received a transfer that has not been
 * executed yet.
 * Pending transfers are executed when this call is being paused or closed,
 * locally or by remote endpoint.
 * If the call is already paused while receiving the transfer request, the
 * transfer immediately occurs.
**/
bool_t linphone_call_has_transfer_pending(const LinphoneCall *call){
	return call->refer_pending;
}

/**
 * Returns call's duration in seconds.
**/
int linphone_call_get_duration(const LinphoneCall *call){
	if (call->media_start_time==0) return 0;
	return time(NULL)-call->media_start_time;
}

/**
 * Returns the call object this call is replacing, if any.
 * Call replacement can occur during call transfers.
 * By default, the core automatically terminates the replaced call and accept the new one.
 * This function allows the application to know whether a new incoming call is a one that replaces another one.
**/
LinphoneCall *linphone_call_get_replaced_call(LinphoneCall *call){
	SalOp *op=sal_call_get_replaces(call->op);
	if (op){
		return (LinphoneCall*)sal_op_get_user_pointer(op);
	}
	return NULL;
}

/**
 * Enable video stream.
**/
void linphone_call_params_enable_video(LinphoneCallParams *cp, bool_t enabled){
	cp->has_video=enabled;
}

/**
 * Returns the audio codec used in the call, described as a PayloadType structure.
**/
const PayloadType* linphone_call_params_get_used_audio_codec(const LinphoneCallParams *cp) {
	return cp->audio_codec;
}

/**
 * Returns the video codec used in the call, described as a PayloadType structure.
**/
const PayloadType* linphone_call_params_get_used_video_codec(const LinphoneCallParams *cp) {
	return cp->video_codec;
}

/**
 * Returns whether video is enabled.
**/
bool_t linphone_call_params_video_enabled(const LinphoneCallParams *cp){
	return cp->has_video;
}

/**
 * Enable sending of real early media (during outgoing calls).
**/
void linphone_call_params_enable_early_media_sending(LinphoneCallParams *cp, bool_t enabled){
	cp->real_early_media=enabled;
}

/**
 * Indicates whether sending of early media was enabled.
**/
bool_t linphone_call_params_early_media_sending_enabled(const LinphoneCallParams *cp){
	return cp->real_early_media;
}

/**
 * Returns true if the call is part of the locally managed conference.
**/
bool_t linphone_call_params_local_conference_mode(const LinphoneCallParams *cp){
	return cp->in_conference;
}

void linphone_call_params_add_custom_header(LinphoneCallParams *params, const char *header_name, const char *header_value){
	params->custom_headers=sal_custom_header_append(params->custom_headers,header_name,header_value);
}

const char *linphone_call_params_get_custom_header(const LinphoneCallParams *params, const char *header_name){
	return sal_custom_header_find(params->custom_headers,header_name);
}

void _linphone_call_params_copy(LinphoneCallParams *ncp, const LinphoneCallParams *cp){
	memcpy(ncp,cp,sizeof(LinphoneCallParams));
	/*
	 * The management of the custom headers is not optimal. We copy everything while ref counting would be more efficient.
	 */
	if (cp->custom_headers) ncp->custom_headers=sal_custom_header_clone(cp->custom_headers);
}

/**
 * Copy existing LinphoneCallParams to a new LinphoneCallParams object.
**/
LinphoneCallParams * linphone_call_params_copy(const LinphoneCallParams *cp){
	LinphoneCallParams *ncp=ms_new0(LinphoneCallParams,1);
	_linphone_call_params_copy(ncp,cp);
	return ncp;
}

void linphone_call_params_uninit(LinphoneCallParams *p){
	if (p->custom_headers) sal_custom_header_free(p->custom_headers);
}

/**
 * Destroy LinphoneCallParams.
**/
void linphone_call_params_destroy(LinphoneCallParams *p){
	linphone_call_params_uninit(p);
	ms_free(p);
}


static int dtmf_tab[16]={'0','1','2','3','4','5','6','7','8','9','*','#','A','B','C','D'};

static void linphone_core_dtmf_received(LinphoneCore *lc, int dtmf){
	if (dtmf<0 || dtmf>15){
		ms_warning("Bad dtmf value %i",dtmf);
		return;
	}
	if (lc->vtable.dtmf_received != NULL)
		lc->vtable.dtmf_received(lc, linphone_core_get_current_call(lc), dtmf_tab[dtmf]);
}

static int find_crypto_index_from_tag(const SalSrtpCryptoAlgo crypto[],unsigned char tag) {
    int i;
    for(i=0; i<SAL_CRYPTO_ALGO_MAX; i++) {
        if (crypto[i].tag == tag) {
            return i;
        }
    }
    return -1;
}

void linphone_call_update_remote_session_id_and_ver(LinphoneCall *call) {
	SalMediaDescription *remote_desc = sal_call_get_remote_media_description(call->op);
	if (remote_desc) {
		call->remote_session_id = remote_desc->session_id;
		call->remote_session_ver = remote_desc->session_ver;
	}
}

void linphone_call_log_completed(LinphoneCall *call){
	LinphoneCore *lc=call->core;

	call->log->duration=time(NULL)-call->start_time;

	if (call->log->status==LinphoneCallMissed){
		char *info;
		lc->missed_calls++;
		info=ortp_strdup_printf(ngettext("You have missed %i call.",
                                         "You have missed %i calls.", lc->missed_calls),
                                lc->missed_calls);
        if (lc->vtable.display_status!=NULL)
            lc->vtable.display_status(lc,info);
		ms_free(info);
	}
	lc->call_logs=ms_list_prepend(lc->call_logs,(void *)call->log);
	if (ms_list_size(lc->call_logs) > lc->max_call_logs){
		MSList *elem,*prevelem=NULL;
		/*find the last element*/
		for(elem=lc->call_logs;elem!=NULL;elem=elem->next){
			prevelem=elem;
		}
		elem=prevelem;
		linphone_call_log_destroy((LinphoneCallLog*)elem->data);
		lc->call_logs=ms_list_remove_link(lc->call_logs,elem);
	}
	if (lc->vtable.call_log_updated!=NULL){
		lc->vtable.call_log_updated(lc,call->log);
	}
}

LinphoneCallState linphone_call_get_transfer_state(LinphoneCall *call) {
	return call->transfer_state;
}

void linphone_call_set_transfer_state(LinphoneCall* call, LinphoneCallState state) {
	if (state != call->transfer_state) {
		LinphoneCore* lc = call->core;
		call->transfer_state = state;
		if (lc->vtable.transfer_state_changed)
			lc->vtable.transfer_state_changed(lc, call, state);
	}
}

/**
 * Returns true if the call is part of the conference.
 * @ingroup conferencing
**/
bool_t linphone_call_is_in_conference(const LinphoneCall *call) {
	return call->params.in_conference;
}
