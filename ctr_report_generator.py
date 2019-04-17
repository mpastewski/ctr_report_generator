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

def enrich(ctr_token, observable, type):
    
    ctr_observe_url = "https://visibility.amp.cisco.com/iroh/iroh-enrich/observe/observables"

    headers = {'Authorization':'Bearer {}'.format(ctr_token),
               'Content-Type':'application/json',
               'Accept':'application/json'}

    payload = '[ {{ "value":"{}"'.format(observable) + ', "type":"{}"'.format(type) + ' } ]'
    response = SESSION.post(url=ctr_observe_url, headers=headers, data=payload)
    response_json = response.json()

    return response_json

#TODO: You do not need two variables to run this fun
def parse_PC_observable(connector_guid, response_json):
#def parse_PC_observable(response_json):

    sha256 = []
    IPs = []

    try:
        for module in response_json['data']:
            if len(module['data']) > 0:
                if 'sightings' in module['data'] and module['data']['sightings']['count'] > 0:
                    docs = module['data']['sightings']['docs']
                    for doc in docs:
                        for relation in doc['relations']:

                            value = relation['related']['value'] 
                            type = relation['related']['type'] 

                            if type == 'sha256' and value not in sha256:
                                sha256.append(value)
                            elif type == 'ip' and value not in IPs:
                                IPs.append(value)
                            else:
                                continue

            else:
                return (sha256, IPs)
    except:
        print("Error")
        #print(connector_guid)

    return (sha256, IPs)
 
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

def main():

   ctr_token = generate_ctr_token()
   computers = get_list_of_computers()
   for pc in computers['data']:
        connector_guid = pc['connector_guid']
        response_json = enrich(ctr_token, connector_guid, "amp_computer_guid")
        (sha256, IPs) = parse_PC_observable(connector_guid, response_json)
        #(sha256, IPs) = parse_PC_observable(response_json)

        print('connector_guid {} sha256 {} IPs {}'.format(connector_guid, sha256, IPs))

if __name__ == '__main__':
    main()

