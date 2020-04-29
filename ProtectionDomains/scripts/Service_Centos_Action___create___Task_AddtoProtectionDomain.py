# REST API call to Prism Central to add VM to protection domain

# setup common variables
uri = "localhost:9440"
cluster_uuid = "@@{platform.status.cluster_reference.uuid}@@"
vm_uuid = "@@{id}@@"
hostname = "@@{calm_application_name}@@"
remote_cluster = "@@{remote_protection_domain_cluster}@@"

# setup credentials
username = '@@{Creds_PrismCentral.username}@@'
username_secret = '@@{Creds_PrismCentral.secret}@@'

# define backup_retention variable given user input
backup_type = "@@{BackupType}@@"

# abusing delimiters in the variable name to improve user experience
backup_type = backup_type.split(" - ")[0]

if backup_type == 'Local':
    backup_retention = 0
elif backup_type == 'Basic':
    backup_retention = 7
elif backup_type == 'Standard':
    backup_retention = 14

###################### DEFINE FUNCTIONS ######################

def rest_call( url, method, username=username, username_secret=username_secret, payload="" ):

    headers = { 'content-type': 'application/json' }

    if payload:
        resp = urlreq(
            url,
            verb=method,
            params=json.dumps(payload),
            auth='BASIC',
            user=username,
            passwd=username_secret,
            headers=headers,
            verify=False
        )
    else:
       resp = urlreq(
            url,
            verb=method,
            auth='BASIC',
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
    else:
        print('Request failed')
        print('Headers: {}'.format(headers))
        print('Payload: {}'.format(json.dumps(payload)))
        print('Status code: {}'.format(resp.status_code))
        print(resp.content)
        exit(1)

################ CREATE PROTECTION DOMAIN ######################

url = "https://{}/PrismGateway/services/rest/v2.0/protection_domains?proxyClusterUuid={}".format(
    uri,
    cluster_uuid
)

method = 'POST'
payload = {"value":""}
payload['value'] = hostname

response = rest_call(url=url,method=method,payload=payload)

print("Created protection domain {}.".format(hostname))

################ WAIT FOR VM AS UNPROTECTED ####################

vm_unprotected = "false"
count = 0
while not vm_unprotected == "true":
    url = "https://{}/PrismGateway/services/rest/v2.0/protection_domains/unprotected_vms?proxyClusterUuid={}".format(
        uri,
        cluster_uuid
    )
    method = 'GET'
    response = rest_call(url=url,method=method)

    # create a list of all vm missing pd
    vm_uuid_missing_pd = []
    for entity in response['entities']:
        vm_uuid_missing_pd.append(entity['uuid'])

    # test for our vm uuid in list of vms missing pd - solves for transient error adding to pd
    if vm_uuid in vm_uuid_missing_pd:
        vm_unprotected = "true"
    else:
        if count == 0:
            print("Waiting for VM to be available before adding to protection domain.")
            count += 1
            sleep(1)

################ ADD VM PROTECTION DOMAIN ######################

payload = {
    "app_consistent_snapshots": False,
    "consistency_group_name": "",
    "ids": [""]
}

payload['ids'] = [vm_uuid]
payload['consistency_group_name'] = hostname

method = 'POST'

url = "https://{}/PrismGateway/services/rest/v2.0/protection_domains/{}/protect_vms?proxyClusterUuid={}".format(
    uri,
    hostname,
    cluster_uuid
)

response = rest_call(url=url,method=method,payload=payload)

print("Added VM {} to protection domain {}.".format(hostname,hostname))

################ ADD PROTECTION DOMAIN SCHEDULE ######################

# an arbitrary historical start date was chosen for simplicity 
payload = {
    "pd_name":"",
    "type":"DAILY",
    "every_nth":1,
    "user_start_time_in_usecs":1574924400000000,
    "timezone_offset":-25200,
    "retention_policy":{
        "local_max_snapshots":7,
        "remote_max_snapshots":{
            "":""
        }
    },
    "app_consistent":False
}

payload['pd_name'] = hostname

if backup_retention == 0:
    # keep 1 day local to prevent prism warnings for pd with no schedule
    payload['retention_policy']['local_max_snapshots'] = 1
    del payload['retention_policy']['remote_max_snapshots']
else:
    payload['retention_policy']['remote_max_snapshots'] = {remote_cluster:backup_retention}

method = 'POST'

url = "https://{}/PrismGateway/services/rest/v2.0/protection_domains/{}/schedules?proxyClusterUuid={}".format(
    uri,
    hostname,
    cluster_uuid
)

response = rest_call(url=url,method=method,payload=payload)

if backup_retention == 0:
    print("Created protection domain schedule with 1 day local retention.")
else:
    print("Created protection domain schedule with 7 days local and {} days remote retention.".format(backup_retention))