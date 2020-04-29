# REST API call to Prism Central to list all available VM snapshots

# setup common variables
uri = 'localhost:9440'
cluster_uuid = '@@{platform.status.cluster_reference.uuid}@@'
vm_uuid = '@@{id}@@'
hostname = '@@{calm_application_name}@@'
remote_cluster = '@@{remote_protection_domain_cluster}@@'

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

################ DETERMINE ID OF LAST SNAPSHOT ###################

url = 'https://{}/PrismGateway/services/rest/v2.0/protection_domains/{}/dr_snapshots?proxyClusterUuid={}'.format(
    uri,
    hostname,
    cluster_uuid
)

method = 'GET'

response = rest_call(url=url,method=method)
entities = response['entities']

# quick and dirty tabular output
print('{0:25}' '{1}'.format('SnapshotID','Time'))
for entity in entities:
    
    snapshot_id = entity['snapshot_id']
    
    # time is in usec and needs trimmed, formatted
    time = str(entity['snapshot_create_time_usecs'])
    time = int(time[:-6:])
    time = _datetime.datetime.fromtimestamp(time).strftime('%x %X')
    print('{0:25}' '{1}'.format(snapshot_id,time))