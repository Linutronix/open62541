/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. */

#include <open62541/plugin/log_stdout.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>

#include "open62541/namespace0_generated.h"
#include "open62541/namespace_di_generated.h"
#include "open62541/namespace_fxac_generated.h"
#include "open62541/namespace_fxcm_generated.h"
#include "open62541/namespace_fxdata_generated.h"
#include "open62541/fxdata_nodeids.h"
#include "open62541/fxac_nodeids.h"

#include <limits.h>
#include <signal.h>
#include <stdlib.h>

UA_Boolean running = true;

#define FE_FOLDER_BROWSE_NAME "FunctionalEntities"

static void
stopHandler(int sign) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "received ctrl-c");
    running = false;
}

static UA_StatusCode
getNodefromPath(UA_Server *server, UA_UInt16 nameSpace, UA_NodeId startNode,
                char *targetName, UA_NodeId *nodeId) {
    UA_RelativePathElement rpe;
    UA_RelativePathElement_init(&rpe);
    rpe.referenceTypeId = UA_NS0ID(HASCOMPONENT);
    rpe.isInverse = false;
    rpe.includeSubtypes = false;
    rpe.targetName = UA_QUALIFIEDNAME(nameSpace, targetName);

    UA_BrowsePath bp;
    UA_BrowsePath_init(&bp);
    bp.startingNode = startNode;
    bp.relativePath.elementsSize = 1;
    bp.relativePath.elements = &rpe;

    UA_BrowsePathResult bpr = UA_Server_translateBrowsePathToNodeIds(server, &bp);
    if(bpr.statusCode != UA_STATUSCODE_GOOD || bpr.targetsSize < 1) {
        return bpr.statusCode;
    }

    *nodeId = bpr.targets[0].targetId.nodeId;
    UA_BrowsePathResult_clear(&bpr);
    return UA_STATUSCODE_GOOD;
}

int
main(int argc, char **argv) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    UA_Server *server = UA_Server_new();
    UA_ServerConfig_setDefault(UA_Server_getConfig(server));

    /* create nodes from nodeset */
    UA_StatusCode retval = 0;
    retval = namespace_di_generated(server);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(
            UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
            "Adding the DI namespace failed. Please check previous error output.");
        goto cleanup;
    }

    size_t fxdata_idx = LONG_MAX;
    retval = namespace_fxdata_generated(server);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                     "Adding the UAFX Data namespace failed. Please check previous "
                     "error output.");
        goto cleanup;
    }
    if(UA_Server_getNamespaceByName(server,
                                    UA_STRING("http://opcfoundation.org/UA/FX/Data/"),
                                    &fxdata_idx) != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                     "Adding the UAFX Data namespace failed. Please check previous "
                     "error output.");
        goto cleanup;
    }
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                "UAFX Data namespace added. Index: %zu", fxdata_idx);

    size_t fxcm_idx = LONG_MAX;
    retval = namespace_fxcm_generated(server);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                     "Adding the UAFX CM namespace failed. Please check previous "
                     "error output.");
        goto cleanup;
    }
    if(UA_Server_getNamespaceByName(server,
                                    UA_STRING("http://opcfoundation.org/UA/FX/CM/"),
                                    &fxcm_idx) != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                     "Adding the UAFX CM namespace failed. Please check previous "
                     "error output.");
        goto cleanup;
    }
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                "UAFX CM namespace added. Index: %zu", fxcm_idx);

    size_t fxac_idx = LONG_MAX;
    retval = namespace_fxac_generated(server);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                     "Adding the UAFX AC namespace failed. Please check previous "
                     "error output.");
        goto cleanup;
    }

    if(UA_Server_getNamespaceByName(server,
                                    UA_STRING("http://opcfoundation.org/UA/FX/AC/"),
                                    &fxac_idx) != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                     "Adding the UAFX AC namespace failed. Please check previous "
                     "error output.");
        goto cleanup;
    }
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                "UAFX AC namespace added. Index: %zu", fxac_idx);

    /* Create an instance of the AutomationComponentType */
    UA_NodeId automationComponentTypeId =
        UA_NODEID_NUMERIC(fxac_idx, UA_FXACID_AUTOMATIONCOMPONENTTYPE);

    UA_NodeId automationComponentInstanceId;
    UA_ObjectAttributes objAttr = UA_ObjectAttributes_default;
    objAttr.displayName = UA_LOCALIZEDTEXT("en-US", "Some Automation Component");

    /* Add the object node (an instance of AutomationComponentType) under the specified
     * ObjectsFolder */
    retval = UA_Server_addObjectNode(
        server, UA_NODEID_NULL, /* Let the server assign a NodeId for the instance */
        UA_NODEID_NUMERIC(fxdata_idx, UA_FXDATAID_FXROOT), /* Parent: fxRoot folder */
        UA_NODEID_NUMERIC(0,
                          UA_NS0ID_ORGANIZES), /* Reference type from parent to child */
        UA_QUALIFIEDNAME(fxdata_idx, "SomeAutomationComponent"),
        automationComponentTypeId, /* TypeDefinition */
        objAttr, NULL,             /* No specific instantiation information */
        &automationComponentInstanceId);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                     "Failed to create Automation Component instance: %s",
                     UA_StatusCode_name(retval));
        goto cleanup;
    }

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                "OPC UA FX Automation Component instance created. NodeId: %N",
                automationComponentInstanceId);

    /* Get FunctionalEntities folder as parent for FunctionalEntity */
    UA_NodeId functionalEntityInstanceId;
    UA_ObjectAttributes feAttr = UA_ObjectAttributes_default;
    feAttr.displayName = UA_LOCALIZEDTEXT("en-US", "Some Functional Entity");

    /* Get the parent nodeid FunctionalEntities */
    UA_NodeId functionalEntitiesNodeId;
    retval = getNodefromPath(server, fxac_idx, automationComponentInstanceId,
                             FE_FOLDER_BROWSE_NAME, &functionalEntitiesNodeId);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                     "Failed to get FunctionalEntities node: %s",
                     UA_StatusCode_name(retval));
        goto cleanup;
    }
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                "FunctionalEntities node found. NodeId: %N", functionalEntitiesNodeId);

    /* Add a new FunctionalEntity Instance to FunctionalEntities folder*/
    UA_NodeId functionalEntityTypeId =
        UA_NODEID_NUMERIC(fxac_idx, UA_FXACID_FUNCTIONALENTITYTYPE);
    retval = UA_Server_addObjectNode(
        server, UA_NODEID_NULL,   /* Let the server assign a NodeId */
        functionalEntitiesNodeId, /* Parent: the FunctionalEntities folder */
        UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT), /* Reference: HasComponent */
        UA_QUALIFIEDNAME(fxdata_idx, "SomeFunctionalEntity"), /* BrowseName */
        functionalEntityTypeId, feAttr, NULL, &functionalEntityInstanceId);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Failed to create Functional Entity instance: %s",
                     UA_StatusCode_name(retval));
        UA_Server_delete(server);
        return (int)retval;
    }

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "Functional Entity instance created. NodeId: %N",
                functionalEntityInstanceId);

    retval = UA_Server_run(server, &running);

cleanup:
    UA_Server_delete(server);
    return retval == UA_STATUSCODE_GOOD ? EXIT_SUCCESS : EXIT_FAILURE;
}
