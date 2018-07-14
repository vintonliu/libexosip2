
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

#include "private.h"
#include <stdlib.h>
#include <stdio.h>
#ifdef HAVE_SIGHANDLER_T
#include <signal.h>
#endif /*HAVE_SIGHANDLER_T*/

#include <string.h>
#if !defined(_WIN32_WCE)
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif /*_WIN32_WCE*/

#undef snprintf

#ifdef HAVE_GETIFADDRS
#include <net/if.h>
#include <ifaddrs.h>
#endif
#include <math.h>


char *int2str(int number)
{
	char *numstr=ms_malloc(10);
	snprintf(numstr,10,"%i",number);
	return numstr;
}


#define UDP_HDR_SZ 8
#define RTP_HDR_SZ 12
#define IP4_HDR_SZ 20   /*20 is the minimum, but there may be some options*/

static void payload_type_set_enable(PayloadType *pt,int value)
{
	if ((value)!=0) payload_type_set_flag(pt,PAYLOAD_TYPE_ENABLED); \
	else payload_type_unset_flag(pt,PAYLOAD_TYPE_ENABLED);
}

static bool_t payload_type_enabled(const PayloadType *pt) {
	return (((pt)->flags & PAYLOAD_TYPE_ENABLED)!=0);
}

int linphone_core_get_payload_type_number(LinphoneCore *lc, const PayloadType *pt){
       return payload_type_get_number(pt);
}

int parse_hostname_to_addr(const char *server, struct sockaddr_storage *ss, socklen_t *socklen){
	struct addrinfo hints,*res=NULL;
	int family = PF_INET;
	int port_int = 3478;
	int ret;
	char port[6];
	char host[NI_MAXHOST];
	char *p1, *p2;
	if ((sscanf(server, "[%64[^]]]:%d", host, &port_int) == 2) || (sscanf(server, "[%64[^]]]", host) == 1)) {
		family = PF_INET6;
	} else {
		p1 = strchr(server, ':');
		p2 = strrchr(server, ':');
		if (p1 && p2 && (p1 != p2)) {
			family = PF_INET6;
			host[NI_MAXHOST-1]='\0';
			strncpy(host, server, sizeof(host) - 1);
		} else if (sscanf(server, "%[^:]:%d", host, &port_int) != 2) {
			host[NI_MAXHOST-1]='\0';
			strncpy(host, server, sizeof(host) - 1);
		}
	}
	snprintf(port, sizeof(port), "%d", port_int);
	memset(&hints,0,sizeof(hints));
	hints.ai_family=family;
	hints.ai_socktype=SOCK_DGRAM;
	hints.ai_protocol=IPPROTO_UDP;
	ret=getaddrinfo(host,port,&hints,&res);
	if (ret!=0){
		ms_error("getaddrinfo() failed for %s:%s : %s",host,port,gai_strerror(ret));
		return -1;
	}
	if (!res) return -1;
	memcpy(ss,res->ai_addr,res->ai_addrlen);
	*socklen=res->ai_addrlen;
	freeaddrinfo(res);
	return 0;
}


static void get_default_addr_and_port(uint16_t componentID, const SalMediaDescription *md, const SalStreamDescription *stream, const char **addr, int *port)
{
	if (componentID == 1) {
		*addr = stream->rtp_addr;
		*port = stream->rtp_port;
	} else if (componentID == 2) {
		*addr = stream->rtcp_addr;
		*port = stream->rtcp_port;
	} else return;
	if ((*addr)[0] == '\0') *addr = md->addr;
}

LinphoneCall * is_a_linphone_call(void *user_pointer){
	LinphoneCall *call=(LinphoneCall*)user_pointer;
	if (call==NULL) return NULL;
	return call->magic==linphone_call_magic ? call : NULL;
}

LinphoneProxyConfig * is_a_linphone_proxy_config(void *user_pointer){
	LinphoneProxyConfig *cfg=(LinphoneProxyConfig*)user_pointer;
	if (cfg==NULL) return NULL;
	return cfg->magic==linphone_proxy_config_magic ? cfg : NULL;
}

#ifdef HAVE_GETIFADDRS

#include <ifaddrs.h>
static int get_local_ip_with_getifaddrs(int type, char *address, int size)
{
	struct ifaddrs *ifp;
	struct ifaddrs *ifpstart;
	int ret = 0;

	if (getifaddrs(&ifpstart) < 0) {
		return -1;
	}
#ifndef __linux
	#define UP_FLAG IFF_UP /* interface is up */
#else
	#define UP_FLAG IFF_RUNNING /* resources allocated */
#endif
	
	for (ifp = ifpstart; ifp != NULL; ifp = ifp->ifa_next) {
		if (ifp->ifa_addr && ifp->ifa_addr->sa_family == type
			&& (ifp->ifa_flags & UP_FLAG) && !(ifp->ifa_flags & IFF_LOOPBACK))
		{
			if(getnameinfo(ifp->ifa_addr,
						(type == AF_INET6) ?
						sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in),
						address, size, NULL, 0, NI_NUMERICHOST) == 0) {
				if (strchr(address, '%') == NULL) {	/*avoid ipv6 link-local addresses */
					/*ms_message("getifaddrs() found %s",address);*/
					ret++;
					break;
				}
			}
		}
	}
	freeifaddrs(ifpstart);
	return ret;
}
#endif


static int get_local_ip_for_with_connect(int type, const char *dest, char *result){
	int err,tmp;
	struct addrinfo hints;
	struct addrinfo *res=NULL;
	struct sockaddr_storage addr;
	struct sockaddr *p_addr=(struct sockaddr*)&addr;
	ortp_socket_t sock;
	socklen_t s;

	memset(&hints,0,sizeof(hints));
	hints.ai_family=(type==AF_INET6) ? PF_INET6 : PF_INET;
	hints.ai_socktype=SOCK_DGRAM;
	/*hints.ai_flags=AI_NUMERICHOST|AI_CANONNAME;*/
	err=getaddrinfo(dest,"5060",&hints,&res);
	if (err!=0){
		ms_error("getaddrinfo() error: %s",gai_strerror(err));
		return -1;
	}
	if (res==NULL){
		ms_error("bug: getaddrinfo returned nothing.");
		return -1;
	}
	sock=socket(res->ai_family,SOCK_DGRAM,0);
	tmp=1;
	err=setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(SOCKET_OPTION_VALUE)&tmp,sizeof(int));
	if (err<0){
		ms_warning("Error in setsockopt: %s",strerror(errno));
	}
	err=connect(sock,res->ai_addr,res->ai_addrlen);
	if (err<0) {
		ms_error("Error in connect: %s",strerror(errno));
 		freeaddrinfo(res);
 		close_socket(sock);
		return -1;
	}
	freeaddrinfo(res);
	res=NULL;
	s=sizeof(addr);
	err=getsockname(sock,(struct sockaddr*)&addr,&s);
	if (err!=0) {
		ms_error("Error in getsockname: %s",strerror(errno));
		close_socket(sock);
		return -1;
	}
	if (p_addr->sa_family==AF_INET){
		struct sockaddr_in *p_sin=(struct sockaddr_in*)p_addr;
		if (p_sin->sin_addr.s_addr==0){
			close_socket(sock);
			return -1;
		}
	}
	err=getnameinfo((struct sockaddr *)&addr,s,result,LINPHONE_IPADDR_SIZE,NULL,0,NI_NUMERICHOST);
	if (err!=0){
		ms_error("getnameinfo error: %s",strerror(errno));
	}
	close_socket(sock);
	ms_message("Local interface to reach %s is %s.",dest,result);
	return 0;
}

int linphone_core_get_local_ip_for(int type, const char *dest, char *result){
	int err;
        strcpy(result,type==AF_INET ? "127.0.0.1" : "::1");
	
	if (dest==NULL){
		if (type==AF_INET)
			dest="87.98.157.38"; /*a public IP address*/
		else dest="2a00:1450:8002::68";
	}
        err=get_local_ip_for_with_connect(type,dest,result);
	if (err==0) return 0;
	
	/* if the connect method failed, which happens when no default route is set, 
	 * try to find 'the' running interface with getifaddrs*/
	
#ifdef HAVE_GETIFADDRS

	/*we use getifaddrs for lookup of default interface */
	int found_ifs;

	found_ifs=get_local_ip_with_getifaddrs(type,result,LINPHONE_IPADDR_SIZE);
	if (found_ifs==1){
		return 0;
	}else if (found_ifs<=0){
		/*absolutely no network on this machine */
		return -1;
	}
#endif
      return 0;  
}

