from urllib.parse import urlparse
import time
import ipaddress
import requests
import json

AMP_CLIENT_ID = "77acbb17e6380dc14dfe"
AMP_API_KEY = "bd1972d1-db07-4486-833b-1ba086f57ec6"
CTR_USER = 'client-0fab5a40-d595-46cf-bf42-1a505bf495eb'
CTR_PASSWORD = 'at1loYXO_YW__BB1Mfj4JOdmrfYYH0iOFdNadxlflL6GvF7_SfB6Wg'
 
SESSION = requests.session()

def generate_ctr_token():

    headers = {'Content-Type':'application/x-www-form-urlencoded',
               'Accept':'application/json'}
    data = {'grant_type':'client_credentials'}
    url = 'https://visibility.amp.cisco.com/iroh/oauth2/token'
    response = requests.post(url=url, auth=(CTR_USER, CTR_PASSWORD), headers=headers, data=data)
    response = response.json()
    access_token = response['access_token']
    return access_token

def get_list_of_computers():

    url = "https://{}:{}@api.amp.cisco.com/v1/computers".format(AMP_CLIENT_ID, AMP_API_KEY)
    response = get(url)
    return response


def get(url):

    try:
        response = requests.get(url, verify=False)

	# Detect any error (status different than 2xx)
        if not response.status_code // 100 == 2:
            return "Error: Unexpected response {}".format(response)
        try:
            return response.json()
        except:
            return "Error: Unexpected JSON {}", format(response.text)
    except requests.exceptions.RequestException as e:
        return "Error {}".format(e)


def enrich(ctr_token, observable, type):
    
    ctr_observe_url = "https://visibility.amp.cisco.com/iroh/iroh-enrich/observe/observables"

    headers = {'Authorization':'Bearer {}'.format(ctr_token),
               'Content-Type':'application/json',
               'Accept':'application/json'}

    payload = '[ {{ "value":"{}"'.format(observable) + ', "type":"{}"'.format(type) + ' } ]'
    response = SESSION.post(url=ctr_observe_url, headers=headers, data=payload)
    try:
        response_json = response.json()
    except:
        print("FATAL ERROR on observable {}".format(observable))
        response_json = ''

    return response_json

def get_indicators(module, vulnerability):

    if 'indicators' in module['data'] and module['data']['indicators']['count'] > 0:
        docs = module['data']['indicators']['docs']
        for doc in docs:
            
            tag = doc['tags'][0]
            value = doc['short_description']

            if tag == 'vulnerability' and value not in vulnerability:
                vulnerability.append(value)

def analyse_artifact(response_json):
    threat_intel = dict()
    attack_patterns = []
    tags = []
    for module in response_json['data']:
        if len(module['data']) > 0:
            if 'judgements' in module['data'] and module['data']['judgements']['count'] > 0:
                docs = module['data']['judgements']['docs']
                for doc in docs:

                    threat_feed = module['module']
                    disposition = doc['disposition_name']
                    threat_intel[threat_feed] = disposition
                
            if 'indicators' in module['data'] and module['data']['indicators']['count'] > 0:
                docs = module['data']['indicators']['docs']
                for doc in docs:
                    description = doc['description']
                    attack_patterns.append(description)
                    
                    try:
                        t = doc['tags']
                        for tag in t:
                            if tag not in tags:
                                tags.append(tag)
                    except:
                        continue

    return (threat_intel, attack_patterns, tags)

def get_sightings(ctr_token, module, sha256, IPs, url, benign):
    
    threat_intel = dict()
    attack_patterns = []
    tags = []

    if 'sightings' in module['data'] and module['data']['sightings']['count'] > 0:
        docs = module['data']['sightings']['docs']
        for doc in docs:
            for relation in doc['relations']:

                value = relation['related']['value'] 
                type = relation['related']['type'] 

                if type == 'url':
                    try:
                        parsed_uri = urlparse(value)
                        value = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
                    except:
                        print('=== URL Parse ERROR {}'.format(value))
                        value = ''

                if type == 'sha256' and value not in sha256 and value not in benign:
                    reputation_json = enrich(ctr_token, value, 'sha256')
                    (threat_intel, attack_patterns, tags) = analyse_artifact(reputation_json)
                    if 'Malicious' in threat_intel.values():
                        sha256.append(value)
                    else:
                        benign.append(value)
                    
                elif type == 'ip' and value not in IPs and value not in benign:
                    if not ipaddress.ip_address(value).is_private:
                        reputation_json = enrich(ctr_token, value, 'ip')
                        (threat_intel, attack_patterns, tags) = analyse_artifact(reputation_json)
                        if 'Malicious' in threat_intel.values():
                            IPs.append(value)
                        else:
                            benign.append(value)

                elif type == 'url' and value not in url and value not in benign:
                    reputation_json = enrich(ctr_token, value, 'url')
                    (threat_intel, attack_patterns, tags) = analyse_artifact(reputation_json)
                    if 'Malicious' in threat_intel.values():
                        url.append(value)
                    else:
                        benign.append(value)
                elif type != 'ip' and type != 'sha256' and type != 'url':
                    print("----- ATTENTION ------- {} {}".format(type, value))

    return (threat_intel, attack_patterns, tags)

def main():

   ctr_token = generate_ctr_token()
   computers = get_list_of_computers()
   for pc in computers['data']:
        connector_guid = pc['connector_guid']
        response_json = enrich(ctr_token, connector_guid, "amp_computer_guid")

        threat_intel = dict()
        attack_patterns = []
        tags = []


        sha256 = []
        IPs = []
        url = []
        vulnerability = []
        benign = []
        
        try:
            for module in response_json['data']:
                if len(module['data']) > 0:
                    try:
                        get_indicators(module, vulnerability)
                    except:
                        print("MY_ERROR")
            
                    try:
                        (threat_intel, attack_pattern) = get_sightings(ctr_token, module, sha256, IPs, url, benign)
                    except:
                        print("Error")
        except:
            print("=== MODULE ERROR === connector_guid {}".format(connector_guid))


        #if sha256 or IPs or url or vulnerability:
        print('connector_guid {} sha256 {} IPs {} url {} vulnerability {} threat_intel {} attack_pattern {}'.format(connector_guid, sha256, IPs, url, vulnerability, threat_intel, attack_patterns))

if __name__ == '__main__':
    start_time = time.time()
    main()
    print("--- %s seconds --- {}".format(time.time() - start_time))
