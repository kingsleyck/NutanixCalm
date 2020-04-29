# REST API call to Prism Central to create an ad hoc / oob VM snapshot

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

def get_last_snapshot_id( uri,hostname,cluster_uuid,rest_call ):
    ################ DETERMINE ID OF LAST SNAPSHOT ###################

    url = 'https://{}/PrismGateway/services/rest/v2.0/protection_domains/{}/dr_snapshots?proxyClusterUuid={}'.format(
        uri,
        hostname,
        cluster_uuid
    )

    method = 'GET'

    response = rest_call(url=url,method=method)
    entities = response['entities']

    snapshot_list = []
    for entity in entities:

        snapshot_list.append(entity['snapshot_id'])

    # sort list of oob snaps descending and capture last snap id
    snapshot_list.sort(reverse=True)
    snapshot_id = snapshot_list[0]
    return snapshot_id

################ TAKE OOB SNAPSHOT IN PD ######################

last_snapshot_id = get_last_snapshot_id(uri=uri,hostname=hostname,cluster_uuid=cluster_uuid,rest_call=rest_call)
snapshot_id = last_snapshot_id

url = 'https://{}/PrismGateway/services/rest/v2.0/protection_domains/{}/oob_schedules?proxyClusterUuid={}'.format(
    uri,
    hostname,
    cluster_uuid
)

method = 'POST'
payload = {
  "app_consistent": False,
  "remote_site_names": [],
  "schedule_start_time_usecs": 123,
  "snapshot_retention_time_secs": 86400
}

schedule_start_time = _datetime.datetime.now().strftime('%s')
payload['schedule_start_time_usecs'] = schedule_start_time

response = rest_call(url=url,method=method,payload=payload)

# loop until the oob snapshot id is returned
while snapshot_id == last_snapshot_id:
    snapshot_id = get_last_snapshot_id(uri=uri,hostname=hostname,cluster_uuid=cluster_uuid,rest_call=rest_call)
    sleep(1)

print('Created snapshot id {} on {}.'.format(snapshot_id,hostname))