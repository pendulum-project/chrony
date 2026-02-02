/*
  chronyd/chronyc - Programs for keeping computer clocks accurate.

 **********************************************************************
 * Copyright (C) Richard P. Curnow  1997-2003
 * Copyright (C) Miroslav Lichvar  2009-2011
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 * 
 **********************************************************************

  =======================================================================

  Functions to do name to IP address conversion

  */

#include "config.h"

#include "sysincl.h"

#include <netdb.h>
#include <resolv.h>
#ifdef FEAT_SRV
#include <getdns/getdns.h>
#endif

#ifdef FEAT_SRV
#include "logging.h"
#include "memory.h"
#endif
#include "nameserv.h"
#include "socket.h"
#include "util.h"

/* ================================================== */

static int address_family = IPADDR_UNSPEC;

#ifdef FEAT_SRV
#define NTS_SERVICE_NAME "_ntske._tcp."

static getdns_context *dns_context = NULL;

static void
reinit()
{
  if (dns_context != NULL)
  {
    getdns_context_destroy(dns_context);
    dns_context = NULL;
  }
  if (getdns_context_create(&dns_context, 1))
    LOG_MESSAGE(LOGS_ERR, "Could not initialize DNS resolver.");
}
#endif

void
DNS_SetAddressFamily(int family)
{
  address_family = family;
}

DNS_Status 
DNS_Name2IPAddress(const char *name, DNS_AddressLookupResult *addrs, int max_addrs, int service_nts)
{
  struct addrinfo hints, *res, *ai;
  int i, result;
  IPAddr ip;

  max_addrs = MIN(max_addrs, DNS_MAX_ADDRESSES);

  for (i = 0; i < max_addrs; i++) {
    addrs[i].ip.family = IPADDR_UNSPEC;
    addrs[i].service_name[0] = 0;
    addrs[i].service_port = 0;
  }

  /* Avoid dealing with the max_addrs=0 edgecase below */
  if (max_addrs < 1)
    return DNS_Success;

  /* Avoid calling getaddrinfo() if the name is an IP address */
  if (UTI_StringToIP(name, &ip)) {
    if (address_family != IPADDR_UNSPEC && ip.family != address_family)
      return DNS_Failure;
    if (max_addrs >= 1)
      addrs[0].ip = ip;
    return DNS_Success;
  }

#ifdef FEAT_SRV
  /* First try if we can do a service record based resolution" */
  if (service_nts) {
    int write_idx;
    getdns_dict *extensions = NULL, *response = NULL;
    getdns_list *service_addresses = NULL;
    getdns_dict *service_entry = NULL;
    getdns_bindata *raw_data = NULL;
    char *service_domain = NULL;
    char *last_name = NULL;
    getdns_return_t getdns_status;
    size_t returned_addresses;
    size_t domain_name_len;

    if (dns_context == NULL) {
      reinit();
      if (dns_context == NULL) {
#ifdef FORCE_DNSRETRY
        return DNS_TryAgain;
#else
        return DNS_Failure;
#endif
      }
    }

    service_domain = Malloc(strlen(NTS_SERVICE_NAME) + strlen(name) + 1);
    strcpy(service_domain, NTS_SERVICE_NAME);
    strcat(service_domain, name);

    if ((extensions = getdns_dict_create()) == NULL)
      LOG_FATAL("Could not allocate memory");
    if (getdns_dict_set_int(extensions, "dnssec_return_only_secure", GETDNS_EXTENSION_TRUE))
      LOG_FATAL("Could not allocate memory");
    getdns_status = getdns_service_sync(dns_context, service_domain, extensions, &response);
    free(service_domain);
    getdns_dict_destroy(extensions);
    if (getdns_status) {
#ifdef FORCE_DNSRETRY
      return DNS_TryAgain;
#else
      return DNS_Failure;
#endif
    }

    if (getdns_dict_get_list(response, "/srv_addresses", &service_addresses))
      LOG_FATAL("Unrecoverable error calling getdns.");
    if (getdns_list_get_length(service_addresses, &returned_addresses))
      LOG_FATAL("Unrecoverable error calling getdns.");

    write_idx = 0;

    for (i = 0; i < returned_addresses; i++) {
      if (getdns_list_get_dict(service_addresses, i, &service_entry))
        LOG_FATAL("Unrecoverable error calling getdns.");
      if (getdns_dict_get_bindata(service_entry, "domain_name", &raw_data))
        LOG_FATAL("Unrecoverable error calling getdns.");
      if (getdns_convert_dns_name_to_fqdn(raw_data, &service_domain))
        LOG_FATAL("Unrecoverable error calling getnds.");
      /* Remove any potential trailing dot as it would interfere with certificate validation*/
      domain_name_len = strlen(service_domain);
      if (service_domain[domain_name_len-1] == '.')
        service_domain[domain_name_len-1] = 0;
      //*Ignore too-long domain names */
      if (strlen(service_domain) >= DNS_SERVICE_NAME_LEN)
        continue;
      /* Ignore repeated names. This is needed to deal with multiple
         addresses from the same service. */
      if (last_name != NULL && strcmp(last_name, service_domain) == 0)
        continue;
      if (getdns_dict_get_bindata(service_entry, "address_data", &raw_data)) {
        // No pre-populated address, recurse to resolve name
        if (DNS_Name2IPAddress(service_domain, &addrs[write_idx], 1, 0) == DNS_Success) {
          strncpy(addrs[write_idx].service_name, service_domain, DNS_SERVICE_NAME_LEN-1);
          write_idx++;
          free(last_name);
          last_name = service_domain;
          service_domain = NULL;
        }
      } else {
        switch (raw_data->size) {
          case sizeof (addrs[write_idx].ip.addr.in4):
            if (address_family != IPADDR_UNSPEC && address_family != IPADDR_INET4)
              continue;
            /* copy first to deal with the fact that alignment of data might not be okay. */
            memcpy(&addrs[write_idx].ip.addr.in4, raw_data->data,
              sizeof (addrs[write_idx].ip.addr.in4));
            addrs[write_idx].ip.addr.in4 = htonl(addrs[write_idx].ip.addr.in4);
            addrs[write_idx].ip.family = IPADDR_INET4;
            strncpy(addrs[write_idx].service_name, service_domain, DNS_SERVICE_NAME_LEN-1);
            write_idx++;
            free(last_name);
            last_name = service_domain;
            service_domain = NULL;
            break;
#ifdef FEAT_IPV6
          case sizeof (addrs[write_idx].ip.addr.in6):
            if (address_family != IPADDR_UNSPEC && address_family != IPADDR_INET6)
              continue;
            memcpy(addrs[write_idx].ip.addr.in6, raw_data->data,
              sizeof(addrs[write_idx].ip.addr.in6));
            addrs[write_idx].ip.family = IPADDR_INET6;
            strncpy(addrs[write_idx].service_name, service_domain, DNS_SERVICE_NAME_LEN-1);
            write_idx++;
            free(last_name);
            last_name = service_domain;
            service_domain = NULL;
            break;
#endif
        }
      }
      free(service_domain);
    }

    if (addrs[0].ip.family != IPADDR_UNSPEC)
      return DNS_Success;
  }

  /* Fall back to regular name resolution */
#endif

  memset(&hints, 0, sizeof (hints));

  switch (address_family) {
    case IPADDR_INET4:
      hints.ai_family = AF_INET;
      break;
#ifdef FEAT_IPV6
    case IPADDR_INET6:
      hints.ai_family = AF_INET6;
      break;
#endif
    default:
      hints.ai_family = AF_UNSPEC;
  }
  hints.ai_socktype = SOCK_DGRAM;

  result = getaddrinfo(name, NULL, &hints, &res);

  if (result) {
#ifdef FORCE_DNSRETRY
    return DNS_TryAgain;
#else
    return result == EAI_AGAIN ? DNS_TryAgain : DNS_Failure;
#endif
  }

  for (ai = res, i = 0; i < max_addrs && ai != NULL; ai = ai->ai_next) {
    switch (ai->ai_family) {
      case AF_INET:
        if (address_family != IPADDR_UNSPEC && address_family != IPADDR_INET4)
          continue;
        addrs[i].ip.family = IPADDR_INET4;
        addrs[i].ip.addr.in4 = ntohl(((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr);
        i++;
        break;
#ifdef FEAT_IPV6
      case AF_INET6:
        if (address_family != IPADDR_UNSPEC && address_family != IPADDR_INET6)
          continue;
        /* Don't return an address that would lose a scope ID */
        if (((struct sockaddr_in6 *)ai->ai_addr)->sin6_scope_id != 0)
          continue;
        addrs[i].ip.family = IPADDR_INET6;
        memcpy(&addrs[i].ip.addr.in6, &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr.s6_addr,
               sizeof (addrs->ip.addr.in6));
        i++;
        break;
#endif
    }
  }

  freeaddrinfo(res);

  return !max_addrs || addrs[0].ip.family != IPADDR_UNSPEC ? DNS_Success : DNS_Failure;
}

/* ================================================== */

int
DNS_IPAddress2Name(IPAddr *ip_addr, char *name, int len)
{
  char *result = NULL;
#ifdef FEAT_IPV6
  struct sockaddr_in6 saddr;
#else
  struct sockaddr_in saddr;
#endif
  IPSockAddr ip_saddr;
  socklen_t slen;
  char hbuf[NI_MAXHOST];

  ip_saddr.ip_addr = *ip_addr;
  ip_saddr.port = 0;

  slen = SCK_IPSockAddrToSockaddr(&ip_saddr, (struct sockaddr *)&saddr, sizeof (saddr));
  if (!getnameinfo((struct sockaddr *)&saddr, slen, hbuf, sizeof (hbuf), NULL, 0, 0))
    result = hbuf;

  if (result == NULL)
    result = UTI_IPToString(ip_addr);
  if (snprintf(name, len, "%s", result) >= len)
    return 0;

  return 1;
}

/* ================================================== */

void
DNS_Reload(void)
{
  res_init();
#ifdef FEAT_SRV
  reinit();
#endif
}

/* ================================================== */
