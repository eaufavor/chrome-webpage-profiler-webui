#!/usr/bin/env python

import json, argparse
import httplib, subprocess, os

def download_files(responseJson, args, agent):
    if args.tarball:
        fUrl = agent+responseJson['tarball']
        p = subprocess.Popen(['wget', fUrl, '-O', 'results.tar.gz'])
        return
    os.makedirs(responseJson['job-id'])
    if 'final-hars' in responseJson:
        for f in responseJson['final-hars']:
            fUrl = agent+f
            p = subprocess.Popen(['wget', '-nv', fUrl], cwd=responseJson['job-id'])
            rc = p.wait()
            if rc != 0:
                print 'Download %s failed' % fUrl
    if not args.final:
        for f in responseJson['files']:
            fUrl = agent+f
            p = subprocess.Popen(['wget', '-nv', fUrl],  cwd=responseJson['job-id'])
            rc = p.wait()
            if rc != 0:
                print 'Download %s failed' % fUrl

def do_retrieve(conn, jobId, wait):
    while True:
        conn.request("GET", '/job?jobid=%s'%jobId)
        poll = conn.getresponse()
        print poll.status, poll.reason
        data = poll.read()
        pollJson = json.loads(data)
        print pollJson
        rc = pollJson['status']
        if rc <= 0 or not wait:
            break
    return pollJson

def get_results(args, responseJson, agent):
    if responseJson['status'] > 0:
        print "Not ready to get results"
        return
    if not args.noresult and not args.harp:
        download_files(responseJson, args, agent)
    if args.harp:
        if 'final-hars' in responseJson:
            for f in responseJson['final-hars']:
                fUrl = agent+f+'p'
                print fUrl
    elif args.noresult:
        print json.dumps(responseJson, indent=4)

def execute(args):
    IP = args.agent.split(':')[0]
    if len(args.agent.split(':')) == 2:
        port = args.agent.split(':')[1]
    else:
        port = 80
    agent = 'http://' + args.agent

    if args.async:
        path = '/async'

    print agent +  path
    headers = {"Content-type": "application/json"}
    conn = httplib.HTTPConnection(IP, port)

    if args.retrieve:
        do_retrieve(conn, args.config, args.wait)

    with open(args.config, 'r') as f:
        config = f.read()

    conn.request("POST", path, config, headers)
    response = conn.getresponse()
    if not args.harp:
        print response.status, response.reason
    data = response.read()
    if response.status != 200:
        print data
        return
    responseJson = json.loads(data)
    if 'message' in responseJson:
        print responseJson['message']
    if args.async:
        print responseJson['message']
        jobId = responseJson['job-id']
        responseJson = do_retrieve(conn, jobId, args.wait)
    get_results(args, responseJson, agent)


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                                     description='A handy tool to perform remote test and retrieve result files')
    parser.add_argument('agent', help='IPaddress:PORT of agent, no "http"')
    parser.add_argument('config', help='Path to the config file, or Job ID in retrieve mode')
    #parser.add_argument('-a', '--analyze', action='store_true', default=False, help='perform TCP analyze on remote test agent as well')
    parser.add_argument('-n', '--noresult', action='store_true', default=False, help='don not try to download result file at all, only show response')
    parser.add_argument('-a', '--async', action='store_true', default=False, help='async mode, POST and leave')
    parser.add_argument('-w', '--wait', action='store_true', default=False, help='poll and wait until job is done in async mode')
    parser.add_argument('-z', '--tarball', action='store_true', default=False, help='download tarball instead of files')
    parser.add_argument('-r', '--retrieve', action='store_true', default=False, help='retrieve the results using job ID')
    parser.add_argument('-f', '--final', action='store_true', default=False, help='only download the final har')
    parser.add_argument('-p', '--harp', action='store_true', default=False, help='just print out the urls of the final har in jsonp format')
    args = parser.parse_args()

    execute(args)

if __name__ == '__main__':
    main()
