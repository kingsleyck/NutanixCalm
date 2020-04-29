# REST API call to Prism Central to remove protection domains
# Leverages the PRISM gateway from Prism Central.

# setup common variables
uri = "localhost:9440"
local_cluster_uuid = "@@{platform.status.cluster_reference.uuid}@@"
vm_uuid = "@@{id}@@"
hostname = "@@{calm_application_name}@@"
remote_cluster = "@@{remote_protection_domain_cluster}@@"

# setup credentials
username = '@@{Creds_PrismCentral.username}@@'
username_secret = '@@{Creds_PrismCentral.secret}@@'

###################### DEFINE FUNCTIONS ######################

def rest_call( url, method, username=username, username_secret=username_secret, payload="" ):

    headers = { 'content-type': 'application/json' }

    if payload:
        resp = urlreq(
            url,
            verb=method,
            params=json.dumps(payload),
            auth="BASIC",
            user=username,
            passwd=username_secret,
            headers=headers,
            verify=False
        )
    else:
       resp = urlreq(
            url,
            verb=method,
            auth="BASIC",
            user=username,
            passwd=username_secret,
            headers=headers,
            verify=False
        )

    if resp.ok:
        try:
            return json.loads(resp.content)
        except:
            return resp.content
    # acceptable error for prot domain doesn't exist
    elif "Protection domain" and "does not exist" in json.loads(resp.content)['message']:
        return
    else:
        print("Request failed")
        print("Headers: {}".format(headers))
        print("Payload: {}".format(json.dumps(payload)))
        print('Status code: {}'.format(resp.status_code))
        print(resp.content)
        exit(1)

################ REMOVE PROTECTION DOMAINS SRC/TARG ######################

# create a list of clusters
cluster_uuids = []
cluster_uuids.append(local_cluster_uuid)

################ GET CLUSTER UUID #################
url = "https://{}/api/nutanix/v3/clusters/list".format(
    uri
)

method = 'POST'
payload = {"kind": "cluster"}

response = rest_call(url=url,method=method,payload=payload)

remote_cluster_uuid = None

for entity in response['entities']:
    if entity['status']['name'] == remote_cluster:
        remote_cluster_uuid = entity['metadata']['uuid']

# append cluster uuid only if exist
if remote_cluster_uuid:
    cluster_uuids.append(remote_cluster_uuid)

for cluster_uuid in cluster_uuids:
    ################ GET CLUSTER FRIENDLY NAME #################

    # retrieve friendly cluster name for more legible console output
    url = "https://{}/api/nutanix/v3/clusters/{}".format(
        uri,
        cluster_uuid
    )

    method = 'GET'
    response = rest_call(url=url,method=method)

    cluster_friendly_name = response['status']['name']

    ################ GET ALL PROTECTION DOMAINS ###################
    url = "https://{}/PrismGateway/services/rest/v2.0/protection_domains/{}?proxyClusterUuid={}".format(
        uri,
        hostname,
        cluster_uuid
    )

    method = 'GET'

    prot_domains_exist = rest_call(url=url,method=method)

    # only execute when a protection domain is found
    if prot_domains_exist:

        ################ REMOVE PROTECTION SCHEDULES #########################
        url = "https://{}/PrismGateway/services/rest/v2.0/protection_domains/{}/schedules?proxyClusterUuid={}".format(
            uri,
            hostname,
            cluster_uuid
        )

        method = 'DELETE'
        response = rest_call(url=url,method=method)

        print("Removed protection domain schedule for {}.".format(hostname))

        ################ GET ALL ONGOING REPLICATIONS ###########################
        url = "https://{}/PrismGateway/services/rest/v2.0/protection_domains/{}/replications?proxyClusterUuid={}".format(
            uri,
            hostname,
            cluster_uuid
        )

        method = 'GET'
        response = rest_call(url=url,method=method)
        entities = response['entities']

        ################ DELETE ALL ONGOING REPLICATIONS ########################

        if entities:
            for entity in entities:

                repl_id = entity['id']

                url = "https://{}/PrismGateway/services/rest/v2.0/protection_domains/{}/replications/{}?proxyClusterUuid={}".format(
                    uri,
                    hostname,
                    repl_id,
                    cluster_uuid
                )

                method = 'DELETE'
                response = rest_call(url=url,method=method)

                print("Removed ongoing snapshot replication from protection domain {} on cluster {}.".format(hostname,cluster_friendly_name))

        ################ GET ALL PD SNAPSHOTS ##################################
        url = "https://{}/PrismGateway/services/rest/v2.0/protection_domains/{}/dr_snapshots?proxyClusterUuid={}".format(
            uri,
            hostname,
            cluster_uuid
        )

        method = 'GET'
        response = rest_call(url=url,method=method)
        entities = response['entities']

        ################ REM ALL LOCAL PD SNAPSHOTS ##############################
        if entities:
            for entity in entities:
                snapshot_id = entity['snapshot_id']

                url = "https://{}/PrismGateway/services/rest/v2.0/protection_domains/{}/dr_snapshots/{}?proxyClusterUuid={}".format(
                    uri,
                    hostname,
                    snapshot_id,
                    cluster_uuid
                )

                method = 'DELETE'

                response = rest_call(url=url,method=method)

                print("Removed protection domain snapshots from cluster {}.".format(cluster_friendly_name))

        ################ REMOVE PROTECTION DOMAIN #################################

        url = "https://{}/PrismGateway/services/rest/v2.0/protection_domains/{}/?proxyClusterUuid={}".format(
            uri,
            hostname,
            cluster_uuid
        )

        method = 'DELETE'
        response = rest_call(url=url,method=method)

        print("Removed protection domain {} from cluster {}.".format(hostname, cluster_friendly_name))
    else:
        print("Protection domain {} not found on cluster {}, removal steps will be skipped.".format(hostname, cluster_friendly_name))