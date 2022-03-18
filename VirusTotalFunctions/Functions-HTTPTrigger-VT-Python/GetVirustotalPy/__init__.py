import logging
import azure.functions as func
import requests
import os
import time
import re
import json
from json import JSONEncoder
from requests.models import Response
import sys

#API Key for VT (There's a better way to do with keyvault however I haven't got round to it yet)
key = ""

def IsHash(s):
    l = len(s)
    p = re.compile('^[a-f0-9]+$', re.IGNORECASE)
    return p.match(s) and (l == 32 or l == 40 or l == 64) # md5, sha1, sha256

#Function to make get request to VT
def VT_request(IOC):
    z = []
    for i in IOC:
        if IsHash(i):
            z.append(MakeRequest(i, 'https://www.virustotal.com/vtapi/v2/file/report'))
        else:
            z.append(MakeRequest(i, 'https://www.virustotal.com/vtapi/v2/url/report'))

    return z

def MakeRequest(resource, url):
    params = {'apikey': key, 'resource': resource}

    logging.info(('Looking up resource {}').format(str(resource)))
    
    answer = {}
    answer["Request"] = resource
    answer["IsPositive"] = False

    try:
        url = requests.get(url, params=params)

        if url.status_code == 200:
            json_response = url.json()
            response = int(json_response.get('response_code'))

            if response == 0:
                answer["Message"] = ('Error from {}').format(str(resource))
            elif response == 1:
                positives = int(json_response.get('positives'))
                if positives < 5:
                    answer["Message"] = ('{} is identfied as clean').format(str(resource))
                else:
                    answer["Message"] = ('{} has 5 or more VT malicious determinations').format(str(resource))
                    answer["Data"] = json.dumps(json_response)
                    answer["IsPositive"] = True
        else:
            message = ('There was an error calling VirusTotal API: Http Status {}').format(url.status_code)
            answer["Message"] = message
            logging.warn(message)

    except Exception as error:
        message = ('There was an unexpected error resolving {}').format(str(resource))
        answer["Message"] = message
        logging.error(message)
        logging.error(error)

    return answer

#Take in HTTP trigger params and execute VT function with IOC arg 
def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Virus Total HTTP trigger function processed a request.')

    IOC = req.params.get('IOC')

    if not IOC:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            IOC = req_body.get('IOC')
 
    if IOC:
        result = VT_request(IOC)
        return func.HttpResponse(
            json.dumps(result),
            mimetype="application/json")

    else:
        return func.HttpResponse(
             "This HTTP triggered function executed successfully. Pass an indicator to trigger function processed a request ",
             status_code=200
        )
