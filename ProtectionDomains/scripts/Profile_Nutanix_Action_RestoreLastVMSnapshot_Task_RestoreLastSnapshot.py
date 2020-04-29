# REST API call to Prism Central to restore a VM from the last snapshot

# setup common variables
uri ='localhost:9440'
cluster_uuid = "@@{platform.status.cluster_reference.uuid}@@"
vm_uuid = '@@{id}@@'
hostname = '@@{calm_application_name}@@'

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

################ RETURN SNAPSHOT ID OF LATEST SNAP #############

url = "https://{}/PrismGateway/services/rest/v2.0/protection_domains/{}/dr_snapshots?proxyClusterUuid={}".format(
    uri,
    hostname,
    cluster_uuid
)

method = 'GET'

response = rest_call(url=url,method=method)
entities = response['entities']
snapshot_list = []

# create list of all snapshot ids
for entity in entities:

    snapshot_list.append(entity['snapshot_id'])

# sort list of snaps descending
snapshot_list.sort(reverse=True)
snapshot_id = snapshot_list[0]

################ RESTORE VM FROM GIVEN SNAPSHOT ID #############

url = "https://{}/PrismGateway/services/rest/v2.0/protection_domains/{}/restore_entities?proxyClusterUuid={}".format(
    uri,
    hostname,
    cluster_uuid
)

method = 'POST'

payload = {
  "replace": True,
  "snapshot_id": "",
  "vm_names": [],
  "path_prefix": ""
}

path_prefix = None
payload['path_prefix'] = path_prefix
payload['snapshot_id'] = snapshot_id
payload['vm_names'] = [hostname]

response = rest_call(url=url,method=method,payload=payload)

print("Restored VM {} from snapshot {}. The VM was restored in a powered off state. Use the Calm Restart action or power on the VM with Prism.".format(hostname,snapshot_id))