#!/usr/bin/env python
#http://www.acmesystems.it/python_httpd
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import json, subprocess, os, time, urlparse

HELLO_MESSAGE = {'message':'hello, please use JSON via POST!'}
ERROR_JSON_MESSAGE = {'message':'POST content type must be application/json!'}
ERROR_BADJSON_MESSAGE = {'message':'POST content must be valid json!'}
ERROR_BADPASS_MESSAGE = {'message':'Wrong secret key!'}
ERROR_CMDERROR_MESSAGE = {'message':'Bad command!'}

ACTIONS = {'run-test', 'self-test'}

TMP = os.path.abspath(r'./tmp')
TEST_DRIVER = os.path.abspath(r'../../chrome-webpage-profiler/test_driver.py')
#TEST_DRIVER = os.path.abspath(r'/bin/cat')

# NOTE: the key is to avoid unintentional access, not to secure the agent
SECRET_KEY = '1a2b'

def run_test(body):

    if not body.get('tests-config'):
        return json.dumps({'message': ERROR_CMDERROR_MESSAGE})

    if not os.path.isdir(TMP):
        try:
            os.makedirs(TMP)
        except Exception as _:
            msg = 'Error making output directory: %s', TMP
            return json.dumps({'message': msg})
    if not os.path.isfile(TEST_DRIVER):
        msg = 'No test driver found at %s' % TEST_DRIVER
        return json.dumps({'message': msg})

    jobId = "%d"%(time.time()*1000)
    jobIdIndex = jobId[-5:]
    jobIdIndexPath = os.path.join(TMP, jobIdIndex)
    jobIdPath = os.path.join(jobIdIndexPath, jobId)
    testConfig = os.path.join(jobIdPath, 'tests.json')

    if not os.path.isdir(jobIdIndexPath):
        try:
            os.makedirs(jobIdIndexPath)
        except Exception as _:
            msg = 'Error making output directory: %s', jobIdIndexPath
            return json.dumps({'message': msg})

    if not os.path.isdir(jobIdPath):
        try:
            os.makedirs(jobIdPath)
        except Exception as _:
            msg = 'Error making output directory: %s', jobIdPath
            return json.dumps({'message': msg})

    tests = body['tests-config']
    with open(testConfig, 'w') as outfile:
        json.dump(tests, outfile, indent=4)

    p = subprocess.Popen([TEST_DRIVER, testConfig], cwd=jobIdPath)
    rc = p.wait()
    if rc == 0:
        response = {'message': 'OK. Done', 'job-id': jobId}
        response['files'] = []
        for f in os.listdir(jobIdPath):
            response['files'].append(os.path.join('/tmp/', jobIdIndex, jobId, f))
        return json.dumps(response)
    else:
        return json.dumps({'message': 'FAIL. return code%d'%rc})

def self_test():
    response = {'message': 'self test done', 'results': {} }
    rc = subprocess.check_output('df -h; exit 0', stderr=subprocess.STDOUT, shell=True)
    response['results']['df'] = rc

    return json.dumps(response)


def execute_POST(body):
    try:
        body = json.loads(body)
    except ValueError as _:
        return json.dumps(ERROR_BADJSON_MESSAGE)

    if body.get('key') != SECRET_KEY:
        return json.dumps(ERROR_BADPASS_MESSAGE)

    if body.get('action') not in ACTIONS:
        return json.dumps(ERROR_CMDERROR_MESSAGE)

    if body['action'] == 'run-test':
        return run_test(body)
    elif body['action'] == 'self-test':
        return self_test()

class S(BaseHTTPRequestHandler):
    def _set_headers(self, mime_type='application/json'):
        self.send_response(200)
        self.send_header('Content-type', mime_type)
        self.end_headers()

    def do_GET(self):
        request = urlparse.urlparse(self.path)
        query = urlparse.parse_qs(request.query)

        makeJsonp = False

        if not request.path.startswith('/tmp'):
            self.send_error(403,'Should not access: %s' % request.path)
            return
        if request.path.endswith(".json") or request.path.endswith(".har"):
            mimeType = 'application/json'
        elif request.path.endswith(".jsonp") or request.path.endswith(".harp"):
            # callable types
            mimeType = 'application/javascript'
            makeJsonp = True
        elif request.path.endswith(".pcap"):
            mimeType = 'application/octet-stream'
        else:
            # the ssl_keylog
            mimeType = 'text/plain'
        path = TMP + request.path.split('/tmp')[1]
        if makeJsonp:
            path = path[:-1] #remove tailing 'p'
        if not os.path.isfile(path):
            # NOTE: this will show clients the internal path (for debug)
            self.send_error(404,'File Not Found: %s' % path)
            return
        self._set_headers(mimeType)
        f = open(path)
        if makeJsonp:
            callback = query.get('callback', [])
            if not callback:
                callback = 'onInputData'
            else:
                callback = callback[0]
            response_body = '{0}({1});'.format(callback, f.read())
            self.wfile.write(response_body)
        else:
            self.wfile.write(f.read())

        return

    def do_HEAD(self):
        self.send_error(501, 'Do not support HEAD')

    def do_POST(self):
        self._set_headers()
        content_len = int(self.headers.getheader('content-length', 0))
        content_type = self.headers.getheader('content-type', 0)
        if content_type.lower() != 'application/json':
            response_body = json.dumps(ERROR_JSON_MESSAGE)
        else:
            post_body = self.rfile.read(content_len)
            response_body = execute_POST(post_body)
        self.wfile.write(response_body)

def run(server_class=HTTPServer, handler_class=S, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print 'Starting httpd...'
    httpd.serve_forever()

if __name__ == "__main__":
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()
