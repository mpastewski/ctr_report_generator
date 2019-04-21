from collections import OrderedDict
from operator import itemgetter   
from reportlab.pdfgen import canvas
import matplotlib.pyplot as plt
import numpy as np
import requests
import json
import urllib3

urllib3.disable_warnings()

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

def get_request_amp4e(param):

    url = "https://{}:{}@api.amp.cisco.com/v1/{}".format(AMP_CLIENT_ID, AMP_API_KEY, param)
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

def get_vulnerability(ctr_token, connector_guid):

    vulnerability = []
    try:
        response_json = enrich(ctr_token, connector_guid, "amp_computer_guid")
    except:
        print("=== NO RESPONSE FROM CTR ===")
        response_json = ''

    try:
        for module in response_json['data']:
            if len(module['data']) > 0:
                try:
                    if 'indicators' in module['data'] and module['data']['indicators']['count'] > 0:
                        docs = module['data']['indicators']['docs']
                        for doc in docs:
                            
                            tag = doc['tags'][0]
                            value = doc['short_description']

                            if tag == 'vulnerability' and value not in vulnerability:
                                vulnerability.append(value)
                except:
                    print("=== ERROR VULNERABILITY DETECTION ===")
                    vulnerability = ''
    except:
        print("=== MODULE ERROR === connector_guid {}".format(connector_guid))

    return vulnerability

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

    return [threat_intel, attack_patterns, tags]


def get_malicious_files(param):

    sha256 = []
    try:
        response_json = get_request_amp4e(param)
    except:
        print("=== NO RESPONSE FROM AMP4E ===")
        response_json = ''

    try:
        for data in response_json['data']:
            if 'file' in data:
                file = data['file']
                disposition = file['disposition']
                file_sha256 = file['identity']['sha256']

                if 'identity' in file and disposition == 'Malicious' and file_sha256 not in sha256:
                    sha256.append(file_sha256)
    except:
        print("===BREAK===")

    return sha256

def generate_diagram(var, title, x_label, y_label, filename):
    var = OrderedDict(sorted(var.items(), key=itemgetter(1), reverse=True))
    plt.bar(range(len(var)), list(var.values()), align='center')
    plt.xticks(range(len(var)), list(var.keys()), rotation=30, fontsize=5)
    plt.xlabel(x_label, fontsize=5)
    plt.ylabel(y_label, fontsize=12)
    plt.title(title, fontsize=12)
    plt.savefig(filename)
    plt.clf()

def count_occurances(list, threshold):
    d = dict()
    for el in list:
        if list.count(el) > threshold:
            d[el] = list.count(el)
    return d

def main():

    result = []
    ctr_token = generate_ctr_token()
    computers = get_request_amp4e('computers')
    for pc in computers['data']:

        connector_guid = pc['connector_guid']
        hostname = pc['hostname']
        param = 'events?connector_guid[]=' + connector_guid

        sha256 = get_malicious_files(param)
        threat_intel = dict()
        attack_patterns = []
        tags = []
        ret = []
        for file in sha256:
            reputation_json = enrich(ctr_token, file, 'sha256')
            r = analyse_artifact(reputation_json)
            ret.append([file, r])

        vulnerability = get_vulnerability(ctr_token, connector_guid)

        try:
            if vulnerability or len(ret[0][1]):
                result.append([[connector_guid, hostname], ret, vulnerability])
        except:
            continue
           
    return result

if __name__ == '__main__':    
    res = main()

    (list_of_tags, list_of_malware) = ([], [])
    malware_per_pc = dict()
    vulnerability = dict()
    for pc in res:
        hostname = pc[0][1]
        vuln = pc[2]
        number_of_malware = len(pc[1])
        if number_of_malware > 2:
            malware_per_pc[hostname] = number_of_malware
        try:
            if vuln:
                vulnerability[hostname] = len(vuln)
            for m in pc[1]:
                try:
                    list_of_malware.append(m[0])
                except:
                    continue
                try:
                    for tag in m[1][2]:
                        list_of_tags.append(tag)
                except:
                    continue
        except:
            continue

    print("Endpoints detected: {}".format(len(res)))
    print("Infections detected: {}".format(len(list_of_malware)))


    tag = count_occurances(list_of_tags, 5)
    malware = count_occurances(list_of_malware, 0)
    
    #TODO: What if max(malware) does not have enough info to display?
    top_threat = max(malware.items(), key=itemgetter(1))[0]
    for pc in res:
        for threat in pc[1]:
            if threat[0] == top_threat:
                top_threat = threat[1]
                break

    generate_diagram(malware, 'Top malware', 'PC', 'Occurance', 'malware.png')
    generate_diagram(malware_per_pc, 'Top PCs with malware', 'PC', 'Malware', 'malware_per_pc.png')
    generate_diagram(vulnerability, 'Top vulnerable endpoints', 'PC', 'Vulnerability', 'vulnerability_per_pc.png')
    generate_diagram(tag, 'Most common tags', 'Tag', '', 'tags.png')

