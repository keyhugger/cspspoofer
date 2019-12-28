import requests
import json
import re
import random
import time
import argparse

param={}
param['agents'] = './flare/useragents.txt'
param['violations'] = './flare/violations.txt'
param['uris'] = './flare/uris.txt'

def parseCsp(cspstring):
    cspstring=cspstring.strip()
    csp={}
    cspEntries=cspstring.split(";")
    cspEntries=list(filter(None, cspEntries))
    for entry in cspEntries:
        entry=entry.strip()
        entrysplitted = entry.split(" ")
        cspkey=entrysplitted.pop(0) #debug purposes
        csp[cspkey.lower()] = entrysplitted
    return csp


def main():

    response = requests.get(url)
    if response.status_code == 200:
        maxlines=response.content.decode('utf-8').count('\n')
        if 'content-security-policy' in response.headers:
            csp=parseCsp(response.headers['content-security-policy'])
            print("Found CSP in Header. Nice :-)")
            if 'report-uri' in csp:
                print("Report-URI is " + csp['report-uri'][0])
                print("Starting Random-timed reports... (CTRL+C to stop)")
                try:
                    while True:
                        reportViolation(csp,response.headers['content-security-policy'],maxlines)
                        print("Waiting.")
                        time.sleep(random.uniform(args.minwait,args.maxwait))
                except KeyboardInterrupt:
                    print('Quitted!')
        elif 'content-security-policy-report-only' in response.headers:
            csp=parseCsp(response.headers['content-security-policy-report-only'])
            print("Found CSP-Report-Only in Header. Good as well :-)") #Insert Why-not-Zoidberg-meme later
            if 'report-uri' in csp:
                print("Report-URI (Report Only) is " + csp['report-uri'][0])
                print("Starting Random-timed reports... (CTRL+C to stop)")
                try:
                    while True:
                        reportViolation(csp,response.headers['content-security-policy'],maxlines)
                        print("Waiting.")
                        time.sleep(random.uniform(args.minwait,args.maxwait))
                except KeyboardInterrupt:
                    print('Quitted!')
        else:
            print("No CSP Header found - cannot parse <meta>-CSP at the moment :-(")

def getRandomUserAgent():
    return random.choice(agents)

def getPossibleViolation():
    return random.choice(violations)

def reportViolation(csp,cspstring,maxline):
    violdirective=random.choice(list(csp.keys()))
    report={
        'blocked-uri':random.choice(uris),
        'document-uri':url,
        'line-number':random.randrange(1,maxline,1),
        'original-policy': cspstring,
        'script-sample':getPossibleViolation(),
        'violated-directive':violdirective + " " + random.choice(csp[violdirective])
    }

    headers = {
    'User-Agent': getRandomUserAgent()
    }
    #print(json.dumps({'csp-report':report})) #Debug Only
    print("Sending Report...")
    requests.post(csp['report-uri'][0], json={'csp-report':report}, headers=headers).status_code

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Flares an Report-URI with random violations.')
    parser.add_argument("URL")
    parser.add_argument('--agents', help='File with User-Agents, 1 Agent per line', default='./flare/useragents.txt')
    parser.add_argument('--reporturis', help='File with a list of URIs inside the report, 1 URI per line', default='./flare/uris.txt')
    parser.add_argument('--violations', help='File with Script Samples to Report, 1 Sample per line', default='./flare/violations.txt')
    parser.add_argument('--minwait', help='Minimal time to wait between Reports in Seconds, eg 1.0', default=1.0, type=float)
    parser.add_argument('--maxwait', help='Maximal time to wait between Reports in Seconds, eg 10.0', default=10.0, type=float)
    
    args = parser.parse_args()
    url = args.URL
    agents = [line.rstrip('\n') for line in open(args.agents)] # globally init predefined stuff for better performance
    violations = [line.rstrip('\n') for line in open(args.violations)]
    uris = [line.rstrip('\n') for line in open(args.reporturis)]
    main()

