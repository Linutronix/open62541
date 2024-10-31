/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 *    Copyright 2017 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 *    Copyright 2017 (c) Thomas Stalder, Blue Time Concept SA
 */

#include "ua_discovery_avahi.h"
#include "ua_server_internal.h"

#ifdef UA_ENABLE_DISCOVERY_MULTICAST

#include "../deps/mp_printf.h"

#include <config.h>

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>

#include <avahi-client/client.h>
#include <avahi-client/lookup.h>

#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>

static struct serverOnNetwork *
mdns_record_add_or_get(UA_DiscoveryManager *dm, const char *record,
                       UA_String serverName, UA_Boolean createNew) {
    UA_UInt32 hashIdx = UA_ByteString_hash(0, (const UA_Byte*)record,
                                           strlen(record)) % SERVER_ON_NETWORK_HASH_SIZE;
    struct serverOnNetwork_hash_entry *hash_entry = dm->serverOnNetworkHash[hashIdx];

    while(hash_entry) {
        size_t maxLen = serverName.length;
        if(maxLen > hash_entry->entry->serverOnNetwork.serverName.length)
            maxLen = hash_entry->entry->serverOnNetwork.serverName.length;

        if(strncmp((char*)hash_entry->entry->serverOnNetwork.serverName.data,
                   (char*)serverName.data, maxLen) == 0)
            return hash_entry->entry;
        hash_entry = hash_entry->next;
    }

    if(!createNew)
        return NULL;

    struct serverOnNetwork *listEntry;
    UA_StatusCode res =
        UA_DiscoveryManager_addEntryToServersOnNetwork(dm, record, serverName, &listEntry);
    if(res != UA_STATUSCODE_GOOD)
        return NULL;

    return listEntry;
}

int avahi_service_register(
    AvahiServiceContext *ctx,
    const char *name,
    const char *type,
    uint16_t port,
    AvahiStringList *txt
) {
    int error;

    if (!ctx->group) {
        ctx->group = avahi_entry_group_new(ctx->client, NULL, NULL);
        if (!ctx->group) {
            fprintf(stderr, "Failed to create entry group.\n");
            return -1;
        }
    }

    // Add the service
    if ((error = avahi_entry_group_add_service_strlst(
            ctx->group,
            AVAHI_IF_UNSPEC,
            AVAHI_PROTO_UNSPEC,
            0,
            name,
            type,
            NULL,       // Default domain
            NULL,       // Default host name
            port,       // Port
            txt         // TXT records
        )) < 0) {
        fprintf(stderr, "Failed to add service: %s\n", avahi_strerror(error));
        return -1;
    }

    // Commit the group
    if ((error = avahi_entry_group_commit(ctx->group)) < 0) {
        fprintf(stderr, "Failed to commit entry group: %s\n", avahi_strerror(error));
        return -1;
    }

    return 0;
}


typedef struct {
    AvahiClient *client;
    AvahiEntryGroup *group;
    char *service_name;
    char *service_type;
    char *domain;
    char *path;
    char *caps;
    void (*conflict_cb)(const char *name, void *userdata);
    void *userdata;
} AvahiServiceData;

static void entry_group_callback(AvahiEntryGroup *g, AvahiEntryGroupState state, void *userdata) {
    AvahiServiceData *data = userdata;
    switch (state) {
        case AVAHI_ENTRY_GROUP_ESTABLISHED:
            // The entry group has been established successfully
            printf("Service '%s' successfully established.\n", data->service_name);
            break;
        case AVAHI_ENTRY_GROUP_COLLISION: {
            // A name collision occurred, adjust the service name
            char *new_name = avahi_alternative_service_name(data->service_name);
            printf("Name collision, renaming service to '%s'\n", new_name);
            avahi_free(data->service_name);
            data->service_name = new_name;

            // Remove the old entry group
            avahi_entry_group_reset(g);

            // Re-register the service with the new name
            // You may call the conflict callback here
            if (data->conflict_cb) {
                data->conflict_cb(data->service_name, data->userdata);
            }

            // Re-add the service with the new name
            // (Implementation depends on your specific case)
            break;
        }
        case AVAHI_ENTRY_GROUP_FAILURE:
            fprintf(stderr, "Entry group failure: %s\n", avahi_strerror(avahi_client_errno(data->client)));
            // Handle the failure (e.g., cleanup and exit)
            break;
        default:
            break;
    }
}

void
mdns_create_txt(UA_DiscoveryManager *dm, const char *fullServiceDomain, const char *path,
                const UA_String *capabilites, const size_t capabilitiesSize,
                void (*conflict)(char *host, int type, void *arg)) {
    AvahiClient *client = dm->mdnsDaemon->client;
    int ret = 0;
    AvahiServiceData data = {0};
    data.client = client;
    data.conflict_cb = conflict_cb;

    // Split the full service domain into service name, type, and domain
    char *service_domain = avahi_strdup(fullServiceDomain);
    char *service_name = NULL;
    char *service_type = NULL;
    char *domain = NULL;

    ret = avahi_service_name_split(service_domain, &service_name, &service_type, &domain);
    if (ret < 0) {
        fprintf(stderr, "Failed to split service domain: %s\n", avahi_strerror(ret));
        avahi_free(service_domain);
        return -1;
    }

    data.service_name = service_name;
    data.service_type = service_type;
    data.domain = domain;

    // Prepare the TXT records
    AvahiStringList *txt = NULL;

    // Handle 'path'
    if (!path || strlen(path) == 0) {
        txt = avahi_string_list_add(txt, "path=/");
    } else {
        char *allocPath = NULL;
        if (path[0] == '/') {
            allocPath = avahi_strdup(path);
        } else {
            allocPath = avahi_malloc(strlen(path) + 2);
            sprintf(allocPath, "/%s", path);
        }
        char *path_kv = avahi_malloc(strlen("path=") + strlen(allocPath) + 1);
        sprintf(path_kv, "path=%s", allocPath);
        txt = avahi_string_list_add(txt, path_kv);
        avahi_free(allocPath);
        avahi_free(path_kv);
    }

    // Handle 'caps'
    if (capabilitiesSize > 0) {
        size_t capsLen = 0;
        for (size_t i = 0; i < capabilitiesSize; i++) {
            capsLen += strlen(capabilities[i]) + 1; // +1 for comma or null terminator
        }

        char *caps = avahi_malloc(capsLen);
        caps[0] = '\0';
        for (size_t i = 0; i < capabilitiesSize; i++) {
            strcat(caps, capabilities[i]);
            if (i < capabilitiesSize - 1) {
                strcat(caps, ",");
            }
        }

        char *caps_kv = avahi_malloc(strlen("caps=") + strlen(caps) + 1);
        sprintf(caps_kv, "caps=%s", caps);
        txt = avahi_string_list_add(txt, caps_kv);
        avahi_free(caps);
        avahi_free(caps_kv);
    } else {
        txt = avahi_string_list_add(txt, "caps=NA");
    }

    // Create an entry group if it doesn't exist
    data.group = avahi_entry_group_new(client, entry_group_callback, &data);
    if (!data.group) {
        fprintf(stderr, "Failed to create entry group: %s\n", avahi_strerror(avahi_client_errno(client)));
        ret = -1;
        goto cleanup;
    }

    // Add the service with TXT records
    ret = avahi_entry_group_add_service_strlst(
        data.group,
        AVAHI_IF_UNSPEC,
        AVAHI_PROTO_UNSPEC,
        0,
        data.service_name,
        data.service_type,
        data.domain,
        NULL,       // Hostname
        0,          // Port (
}



static UA_StatusCode
UA_Discovery_addRecord(UA_DiscoveryManager *dm, const UA_String servername,
                       const UA_String hostname, UA_UInt16 port,
                       const UA_String path, const UA_DiscoveryProtocol protocol,
                       UA_Boolean createTxt, const UA_String* capabilites,
                       const size_t capabilitiesSize,
                       UA_Boolean isSelf) {
    /* We assume that the hostname is not an IP address, but a valid domain
     * name. It is required by the OPC UA spec (see Part 12, DiscoveryURL to DNS
     * SRV mapping) to always use the hostname instead of the IP address. */

    if(capabilitiesSize > 0 && !capabilites)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    if(hostname.length == 0 || servername.length == 0)
        return UA_STATUSCODE_BADOUTOFRANGE;

    /* Use a limit for the hostname length to make sure full string fits into 63
     * chars (limited by DNS spec) */
    if(hostname.length + servername.length + 1 > 63) { /* include dash between servername-hostname */
        UA_LOG_WARNING(dm->sc.server->config.logging, UA_LOGCATEGORY_DISCOVERY,
                       "Multicast DNS: Combination of hostname+servername exceeds "
                       "maximum of 62 chars. It will be truncated.");
    } else if(hostname.length > 63) {
        UA_LOG_WARNING(dm->sc.server->config.logging, UA_LOGCATEGORY_DISCOVERY,
                       "Multicast DNS: Hostname length exceeds maximum of 63 chars. "
                       "It will be truncated.");
    }


    /* [servername]-[hostname]._opcua-tcp._tcp.local. */
    char fullServiceDomain[63+24];
    createFullServiceDomain(fullServiceDomain, 63+24, servername, hostname);

    UA_Boolean exists = UA_Discovery_recordExists(dm, fullServiceDomain,
                                                  port, protocol);
    if(exists == true)
        return UA_STATUSCODE_GOOD;

    UA_LOG_INFO(dm->sc.server->config.logging, UA_LOGCATEGORY_DISCOVERY,
                "Multicast DNS: add record for domain: %s", fullServiceDomain);

    if(isSelf && dm->selfFqdnMdnsRecord.length == 0) {
        dm->selfFqdnMdnsRecord = UA_STRING_ALLOC(fullServiceDomain);
        if(!dm->selfFqdnMdnsRecord.data)
            return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    UA_String serverName = {
        UA_MIN(63, servername.length + hostname.length + 1),
        (UA_Byte*) fullServiceDomain};

    struct serverOnNetwork *listEntry;
    /* The servername is servername + hostname. It is the same which we get
     * through mDNS and therefore we need to match servername */
    UA_StatusCode retval =
        UA_DiscoveryManager_addEntryToServersOnNetwork(dm, fullServiceDomain,
                                                       serverName, &listEntry);
    if(retval != UA_STATUSCODE_GOOD &&
       retval != UA_STATUSCODE_BADALREADYEXISTS)
        return retval;

    /* If entry is already in list, skip initialization of capabilities and txt+srv */
    if(retval != UA_STATUSCODE_BADALREADYEXISTS) {
        /* if capabilitiesSize is 0, then add default cap 'NA' */
        listEntry->serverOnNetwork.serverCapabilitiesSize = UA_MAX(1, capabilitiesSize);
        listEntry->serverOnNetwork.serverCapabilities = (UA_String *)
            UA_Array_new(listEntry->serverOnNetwork.serverCapabilitiesSize,
                         &UA_TYPES[UA_TYPES_STRING]);
        if(!listEntry->serverOnNetwork.serverCapabilities)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        if(capabilitiesSize == 0) {
            UA_String na;
            na.length = 2;
            na.data = (UA_Byte *) (uintptr_t) "NA";
            UA_String_copy(&na, &listEntry->serverOnNetwork.serverCapabilities[0]);
        } else {
            for(size_t i = 0; i < capabilitiesSize; i++)
                UA_String_copy(&capabilites[i],
                               &listEntry->serverOnNetwork.serverCapabilities[i]);
        }

        listEntry->txtSet = true;

        const size_t newUrlSize = 10 + hostname.length + 8 + path.length + 1;
        UA_STACKARRAY(char, newUrl, newUrlSize);
        memset(newUrl, 0, newUrlSize);
        if(path.length > 0) {
            mp_snprintf(newUrl, newUrlSize, "opc.tcp://%S:%d/%S", hostname, port, path);
        } else {
            mp_snprintf(newUrl, newUrlSize, "opc.tcp://%S:%d", hostname, port);
        }
        listEntry->serverOnNetwork.discoveryUrl = UA_String_fromChars(newUrl);
        listEntry->srvSet = true;
    }

    /* _services._dns-sd._udp.local. PTR _opcua-tcp._tcp.local */

    /* check if there is already a PTR entry for the given service. */

    /* _opcua-tcp._tcp.local. PTR [servername]-[hostname]._opcua-tcp._tcp.local. */

        // Prepare TXT records
    AvahiStringList *txt = NULL;
    txt = avahi_string_list_add(txt, "key1=value1");
    txt = avahi_string_list_add(txt, "key2=value2");

    // Register a service
    if (avahi_service_register(ctx, "My Service", "_opcua-tcp._tcp", 1234, txt) < 0) {
        fprintf(stderr, "Failed to register service.\n");
        avahi_string_list_free(txt);
        avahi_service_stop(ctx);
        return 1;
    }




    mdns_record_t *r =
        mdns_find_record(dm->mdnsDaemon, QTYPE_PTR,
                         "_opcua-tcp._tcp.local.", fullServiceDomain);
    if(!r) {
        r = mdnsd_shared(dm->mdnsDaemon, "_opcua-tcp._tcp.local.",
                         QTYPE_PTR, 600);
        mdnsd_set_host(dm->mdnsDaemon, r, fullServiceDomain);
    }

    /* The first 63 characters of the hostname (or less) */
    size_t maxHostnameLen = UA_MIN(hostname.length, 63);
    char localDomain[65];
    memcpy(localDomain, hostname.data, maxHostnameLen);
    localDomain[maxHostnameLen] = '.';
    localDomain[maxHostnameLen+1] = '\0';

    /* [servername]-[hostname]._opcua-tcp._tcp.local. 86400 IN SRV 0 5 port [hostname]. */
    r = mdnsd_unique(dm->mdnsDaemon, fullServiceDomain,
                     QTYPE_SRV, 600, UA_Discovery_multicastConflict, dm);
    mdnsd_set_srv(dm->mdnsDaemon, r, 0, 0, port, localDomain);

    /* A/AAAA record for all ip addresses.
     * [servername]-[hostname]._opcua-tcp._tcp.local. A [ip].
     * [hostname]. A [ip]. */
    mdns_set_address_record(dm, fullServiceDomain, localDomain);

    /* TXT record: [servername]-[hostname]._opcua-tcp._tcp.local. TXT path=/ caps=NA,DA,... */
    UA_STACKARRAY(char, pathChars, path.length + 1);
    if(createTxt) {
        if(path.length > 0)
            memcpy(pathChars, path.data, path.length);
        pathChars[path.length] = 0;
        mdns_create_txt(dm, fullServiceDomain, pathChars, capabilites,
                        capabilitiesSize, UA_Discovery_multicastConflict);
    }

    return UA_STATUSCODE_GOOD;
}


UA_StatusCode
UA_DiscoveryManager_addEntryToServersOnNetwork(UA_DiscoveryManager *dm,
                                               const char *fqdnMdnsRecord,
                                               UA_String serverName,
                                               struct serverOnNetwork **addedEntry) {
    struct serverOnNetwork *entry =
            mdns_record_add_or_get(dm, fqdnMdnsRecord, serverName, false);
    if(entry) {
        if(addedEntry != NULL)
            *addedEntry = entry;
        return UA_STATUSCODE_BADALREADYEXISTS;
    }

    UA_LOG_DEBUG(dm->sc.server->config.logging, UA_LOGCATEGORY_SERVER,
                "Multicast DNS: Add entry to ServersOnNetwork: %s (%S)",
                 fqdnMdnsRecord, serverName);

    struct serverOnNetwork *listEntry = (serverOnNetwork*)
            UA_malloc(sizeof(struct serverOnNetwork));
    if(!listEntry)
        return UA_STATUSCODE_BADOUTOFMEMORY;


    UA_EventLoop *el = dm->sc.server->config.eventLoop;
    listEntry->created = el->dateTime_now(el);
    listEntry->pathTmp = NULL;
    listEntry->txtSet = false;
    listEntry->srvSet = false;
    UA_ServerOnNetwork_init(&listEntry->serverOnNetwork);
    listEntry->serverOnNetwork.recordId = dm->serverOnNetworkRecordIdCounter;
    UA_StatusCode res = UA_String_copy(&serverName, &listEntry->serverOnNetwork.serverName);
    if(res != UA_STATUSCODE_GOOD) {
        UA_free(listEntry);
        return res;
    }
    dm->serverOnNetworkRecordIdCounter++;
    if(dm->serverOnNetworkRecordIdCounter == 0)
        dm->serverOnNetworkRecordIdLastReset = el->dateTime_now(el);
    listEntry->lastSeen = el->dateTime_nowMonotonic(el);

    /* add to hash */
    UA_UInt32 hashIdx = UA_ByteString_hash(0, (const UA_Byte*)fqdnMdnsRecord,
                                           strlen(fqdnMdnsRecord)) % SERVER_ON_NETWORK_HASH_SIZE;
    struct serverOnNetwork_hash_entry *newHashEntry = (struct serverOnNetwork_hash_entry*)
            UA_malloc(sizeof(struct serverOnNetwork_hash_entry));
    if(!newHashEntry) {
        UA_String_clear(&listEntry->serverOnNetwork.serverName);
        UA_free(listEntry);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    newHashEntry->next = dm->serverOnNetworkHash[hashIdx];
    dm->serverOnNetworkHash[hashIdx] = newHashEntry;
    newHashEntry->entry = listEntry;

    LIST_INSERT_HEAD(&dm->serverOnNetwork, listEntry, pointers);
    if(addedEntry != NULL)
        *addedEntry = listEntry;

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_DiscoveryManager_removeEntryFromServersOnNetwork(UA_DiscoveryManager *dm,
                                                    const char *fqdnMdnsRecord,
                                                    UA_String serverName) {
    UA_LOG_DEBUG(dm->sc.server->config.logging, UA_LOGCATEGORY_SERVER,
                 "Multicast DNS: Remove entry from ServersOnNetwork: %s (%S)",
                 fqdnMdnsRecord, serverName);

    struct serverOnNetwork *entry =
            mdns_record_add_or_get(dm, fqdnMdnsRecord, serverName, false);
    if(!entry)
        return UA_STATUSCODE_BADNOTFOUND;

    UA_String recordStr;
    // Cast away const because otherwise the pointer cannot be assigned.
    // Be careful what you do with recordStr!
    recordStr.data = (UA_Byte*)(uintptr_t)fqdnMdnsRecord;
    recordStr.length = strlen(fqdnMdnsRecord);

    /* remove from hash */
    UA_UInt32 hashIdx = UA_ByteString_hash(0, (const UA_Byte*)recordStr.data,
                                           recordStr.length) % SERVER_ON_NETWORK_HASH_SIZE;
    struct serverOnNetwork_hash_entry *hash_entry = dm->serverOnNetworkHash[hashIdx];
    struct serverOnNetwork_hash_entry *prevEntry = hash_entry;
    while(hash_entry) {
        if(hash_entry->entry == entry) {
            if(dm->serverOnNetworkHash[hashIdx] == hash_entry)
                dm->serverOnNetworkHash[hashIdx] = hash_entry->next;
            else if(prevEntry)
                prevEntry->next = hash_entry->next;
            break;
        }
        prevEntry = hash_entry;
        hash_entry = hash_entry->next;
    }
    UA_free(hash_entry);

    if(dm->serverOnNetworkCallback &&
        !UA_String_equal(&dm->selfFqdnMdnsRecord, &recordStr))
        dm->serverOnNetworkCallback(&entry->serverOnNetwork, false,
                                    entry->txtSet,
                                    dm->serverOnNetworkCallbackData);

    /* Remove from list */
    LIST_REMOVE(entry, pointers);
    UA_ServerOnNetwork_clear(&entry->serverOnNetwork);
    if(entry->pathTmp) {
        UA_free(entry->pathTmp);
        entry->pathTmp = NULL;
    }
    UA_free(entry);
    return UA_STATUSCODE_GOOD;
}

static void
mdns_append_path_to_url(UA_String *url, const char *path) {
    size_t pathLen = strlen(path);
    size_t newUrlLen = url->length + pathLen; //size of the new url string incl. the path 
    /* todo: malloc may fail: return a statuscode */
    char *newUrl = (char *)UA_malloc(url->length + pathLen);
    memcpy(newUrl, url->data, url->length);
    memcpy(newUrl + url->length, path, pathLen);
    UA_String_clear(url);
    url->length = newUrlLen;
    url->data = (UA_Byte *) newUrl;
}

typedef enum {
    UA_DISCOVERY_TCP,    /* OPC UA TCP mapping */
    UA_DISCOVERY_TLS     /* OPC UA HTTPS mapping */
} UA_DiscoveryProtocol;


static UA_StatusCode
addMdnsRecordForNetworkLayer(UA_DiscoveryManager *dm, const UA_String serverName,
                             const UA_String *discoveryUrl) {
    UA_String hostname = UA_STRING_NULL;
    char hoststr[256]; /* check with UA_MAXHOSTNAME_LENGTH */
    UA_UInt16 port = 4840;
    UA_String path = UA_STRING_NULL;
    UA_StatusCode retval =
        UA_parseEndpointUrl(discoveryUrl, &hostname, &port, &path);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(dm->sc.server->config.logging, UA_LOGCATEGORY_DISCOVERY,
                       "Server url is invalid: %S", *discoveryUrl);
        return retval;
    }

    if(hostname.length == 0) {
        gethostname(hoststr, sizeof(hoststr)-1);
        hoststr[sizeof(hoststr)-1] = '\0';
        hostname.data = (unsigned char *) hoststr;
        hostname.length = strlen(hoststr);
    }
    retval = UA_Discovery_addRecord(dm, serverName, hostname, port, path, UA_DISCOVERY_TCP, true,
                                    dm->sc.server->config.mdnsConfig.serverCapabilities,
                                    dm->sc.server->config.mdnsConfig.serverCapabilitiesSize, true);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(dm->sc.server->config.logging, UA_LOGCATEGORY_DISCOVERY,
                       "Cannot add mDNS Record: %s", UA_StatusCode_name(retval));
        return retval;
    }
    return UA_STATUSCODE_GOOD;
}

#ifndef IN_ZERONET
#define IN_ZERONET(addr) ((addr & IN_CLASSA_NET) == 0)
#endif

void
UA_DiscoveryManager_startMulticast(UA_DiscoveryManager *dm) {
    AvahiServiceContext *ctx = dm->ctx;
    ctx = malloc(sizeof(AvahiServiceContext));
    if (!ctx) {
        UA_LOG_ERROR(dm->sc.server->config.logging, UA_LOGCATEGORY_DISCOVERY,
                     "Failed to allocate memory for AvahiServiceContext");
        return;
    }

    ctx->simple_poll = avahi_simple_poll_new();
    if (!ctx->simple_poll) {
        UA_LOG_ERROR(dm->sc.server->config.logging, UA_LOGCATEGORY_DISCOVERY,
                     "Failed to create simple poll");
        free(ctx);
        return;
    }

    ctx->client = avahi_client_new(avahi_simple_poll_get(ctx->simple_poll), 0, client_callback, NULL, &error);
    if (!ctx->client) {
        UA_LOG_ERROR(dm->sc.server->config.logging, UA_LOGCATEGORY_DISCOVERY,
                     "Failed to create client: %s", avahi_strerror(error));
        avahi_simple_poll_free(ctx->simple_poll);
        free(ctx);
        return;
    }

    ctx->group = NULL;
    ctx->browser = NULL;

    /* Add record for the server itself */
    UA_String appName = dm->sc.server->config.mdnsConfig.mdnsServerName;
    for(size_t i = 0; i < dm->sc.server->config.serverUrlsSize; i++)
        addMdnsRecordForNetworkLayer(dm, appName, &dm->sc.server->config.serverUrls[i]);

    /* Send a multicast probe to find any other OPC UA server on the network
     * through mDNS */
    mdnsd_query(dm->mdnsDaemon, "_opcua-tcp._tcp.local.",
                QTYPE_PTR,discovery_multicastQueryAnswer, dm->sc.server);
}

void
UA_DiscoveryManager_stopMulticast(UA_DiscoveryManager *dm) {
    UA_Server *server = dm->sc.server;
    for(size_t i = 0; i < server->config.serverUrlsSize; i++) {
        UA_String hostname = UA_STRING_NULL;
        UA_String path = UA_STRING_NULL;
        UA_UInt16 port = 0;

        UA_StatusCode retval =
            UA_parseEndpointUrl(&server->config.serverUrls[i],
                                &hostname, &port, &path);

        if(retval != UA_STATUSCODE_GOOD || hostname.length == 0)
            continue;

        UA_Discovery_removeRecord(dm, server->config.mdnsConfig.mdnsServerName,
                                  hostname, port, true);
    }

    /* Stop the cyclic polling callback */
    if(dm->mdnsCallbackId != 0) {
        UA_EventLoop *el = server->config.eventLoop;
        if(el) {
            el->removeTimer(el, dm->mdnsCallbackId);
            dm->mdnsCallbackId = 0;
        }
    }

    /* Close the socket */
    if(dm->cm) {
        if(dm->mdnsSendConnection)
            dm->cm->closeConnection(dm->cm, dm->mdnsSendConnection);
        for(size_t i = 0; i < UA_MAXMDNSRECVSOCKETS; i++)
            if(dm->mdnsRecvConnections[i] != 0)
                dm->cm->closeConnection(dm->cm, dm->mdnsRecvConnections[i]);
    }
}

void
UA_Discovery_updateMdnsForDiscoveryUrl(UA_DiscoveryManager *dm, const UA_String serverName,
                                       const UA_MdnsDiscoveryConfiguration *mdnsConfig,
                                       const UA_String discoveryUrl,
                                       UA_Boolean isOnline, UA_Boolean updateTxt) {
    UA_String hostname = UA_STRING_NULL;
    UA_UInt16 port = 4840;
    UA_String path = UA_STRING_NULL;
    UA_StatusCode retval =
        UA_parseEndpointUrl(&discoveryUrl, &hostname, &port, &path);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(dm->sc.server->config.logging, UA_LOGCATEGORY_DISCOVERY,
                       "Server url invalid: %S", discoveryUrl);
        return;
    }

    if(!isOnline) {
        UA_StatusCode removeRetval =
                UA_Discovery_removeRecord(dm, serverName, hostname,
                                          port, updateTxt);
        if(removeRetval != UA_STATUSCODE_GOOD)
            UA_LOG_WARNING(dm->sc.server->config.logging, UA_LOGCATEGORY_DISCOVERY,
                           "Could not remove mDNS record for hostname %S", serverName);
        return;
    }

    UA_String *capabilities = NULL;
    size_t capabilitiesSize = 0;
    if(mdnsConfig) {
        capabilities = mdnsConfig->serverCapabilities;
        capabilitiesSize = mdnsConfig->serverCapabilitiesSize;
    }

    UA_StatusCode addRetval =
        UA_Discovery_addRecord(dm, serverName, hostname,
                               port, path, UA_DISCOVERY_TCP, updateTxt,
                               capabilities, capabilitiesSize, false);
    if(addRetval != UA_STATUSCODE_GOOD)
        UA_LOG_WARNING(dm->sc.server->config.logging, UA_LOGCATEGORY_DISCOVERY,
                       "Could not add mDNS record for hostname %S", serverName);
}

void
UA_Server_setServerOnNetworkCallback(UA_Server *server,
                                     UA_Server_serverOnNetworkCallback cb,
                                     void* data) {
    UA_LOCK(&server->serviceMutex);
    UA_DiscoveryManager *dm = (UA_DiscoveryManager*)
        getServerComponentByName(server, UA_STRING("discovery"));
    if(dm) {
        dm->serverOnNetworkCallback = cb;
        dm->serverOnNetworkCallbackData = data;
    }
    UA_UNLOCK(&server->serviceMutex);
}

static void
UA_Discovery_multicastConflict(char *name, int type, void *arg) {
    /* In case logging is disabled */
    (void)name;
    (void)type;

    UA_DiscoveryManager *dm = (UA_DiscoveryManager*) arg;
    UA_LOG_ERROR(dm->sc.server->config.logging, UA_LOGCATEGORY_DISCOVERY,
                 "Multicast DNS name conflict detected: "
                 "'%s' for type %d", name, type);
}

/* Create a service domain with the format [servername]-[hostname]._opcua-tcp._tcp.local. */
static void
createFullServiceDomain(char *outServiceDomain, size_t maxLen,
                        UA_String servername, UA_String hostname) {
    maxLen -= 24; /* the length we have remaining before the opc ua postfix and
                   * the trailing zero */

    /* Can we use hostname and servername with full length? */
    if(hostname.length + servername.length + 1 > maxLen) {
        if(servername.length + 2 > maxLen) {
            servername.length = maxLen;
            hostname.length = 0;
        } else {
            hostname.length = maxLen - servername.length - 1;
        }
    }

    size_t offset = 0;
    if(hostname.length > 0) {
        mp_snprintf(outServiceDomain, maxLen + 1, "%S-%S", servername, hostname);
        offset = servername.length + hostname.length + 1;
        //replace all dots with minus. Otherwise mDNS is not valid
        for(size_t i = servername.length+1; i < offset; i++) {
            if(outServiceDomain[i] == '.')
                outServiceDomain[i] = '-';
        }
    } else {
        mp_snprintf(outServiceDomain, maxLen + 1, "%S", servername);
        offset = servername.length;
    }
    mp_snprintf(&outServiceDomain[offset], 24, "._opcua-tcp._tcp.local.");
}



#endif /* UA_ENABLE_DISCOVERY_MULTICAST */
