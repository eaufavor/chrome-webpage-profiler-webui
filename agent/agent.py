#!/usr/bin/env python
#http://www.acmesystems.it/python_httpd
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import json, subprocess, os, time, urlparse, re

HELLO_MESSAGE = {'message':'hello, please use JSON via POST!'}
ERROR_JSON_MESSAGE = {'message':'POST content type must be application/json!'}
ERROR_BADJSON_MESSAGE = {'message':'POST content must be valid json!'}
ERROR_BADPASS_MESSAGE = {'message':'Wrong secret key!'}
ERROR_CMDERROR_MESSAGE = {'message':'Bad command!'}

ACTIONS = {'run-test', 'self-test', 'run-test-and-analyse'}


# TODO: dryrun to test these paths
TMP = os.path.abspath(r'./tmp')
TEST_DRIVER = os.path.abspath(r'../../chrome-webpage-profiler/test_driver.py')
H2_ANALYZER = os.path.abspath(r'../../http2-dump-anatomy/http_traffic_analyzer.py')
MERGE_TOOL = os.path.abspath(r'../../chrome-webpage-profiler/merge_har.py')
TSHARK = os.path.abspath(r'../../wireshark-1.99.7/tshark')

ANALYSE_CMD = '{H2_ANALYZER} -g {{pcapfile}} -k {{keyfile}} -b {TSHARK} | {MERGE_TOOL} -h {{harfile}} -o {{finalhar}}'
ANALYSE_CMD = ANALYSE_CMD.format(H2_ANALYZER=H2_ANALYZER, TSHARK=TSHARK, MERGE_TOOL=MERGE_TOOL)
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
            return json.dumps({'message': msg, 'status': -1})
    if not os.path.isfile(TEST_DRIVER):
        msg = 'No test driver found at %s' % TEST_DRIVER
        return json.dumps({'message': msg, 'status': -1})

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
            return json.dumps({'message': msg, 'status': -2})

    if not os.path.isdir(jobIdPath):
        try:
            os.makedirs(jobIdPath)
        except Exception as _:
            msg = 'Error making output directory: %s', jobIdPath
            return json.dumps({'message': msg, 'status': -2})

    tests = body['tests-config']
    with open(testConfig, 'w') as outfile:
        json.dump(tests, outfile, indent=4)

    p = subprocess.Popen([TEST_DRIVER, testConfig], cwd=jobIdPath)
    rc = p.wait()
    if rc == 0:
        response = {'message': 'OK. Done', 'job-id': jobId,
                    'status': rc, '_job-path': jobIdPath}
        response['files'] = []
        for f in os.listdir(jobIdPath):
            response['files'].append(os.path.join('/tmp/', jobIdIndex, jobId, f))
        return json.dumps(response)
    else:
        return json.dumps({'message': 'FAIL. return code%d'%rc, 'status': rc})

### the following two helper fuctions are from chrome-webpage-profiler
### NOTE: remmember to sync them if those are updated
### SYNC START
def _sanitize_url(url):
    '''Returns a version of the URL suitable for use in a file name.'''
    return re.sub(r'[/\;,><&*:%=+@!#^()|?^]', '-', url)

def _outfile_path(working_dir, url, suffix=None, trial=None):
    '''Returns a path for an output file (e.g., HAR, screenshot, pcap)'''
    filename = _sanitize_url(url)
    if trial:
        filename += '_trial%d' % trial
    if suffix:
        filename += suffix
    return os.path.join(working_dir, filename)
### SYNC END

def find_dump_har_pairs(working_dir, config_file):
    pairs = []
    with open(config_file, 'r') as f:
        config = json.load(f)

    for test in config['tests']:
        pcapFileName = test.get('packet_capture_file_name', test['url'])
        harFileName = test.get('har_file_name', test['url'])
        for i in range(0, test.get('num_trials', 1)):
            pcapFileName = _outfile_path(working_dir, pcapFileName, suffix='.pcap', trial=i)
            harFileName = _outfile_path(working_dir, harFileName, suffix='.har', trial=i)
            if (not os.path.isfile(pcapFileName)) or (not os.path.isfile(harFileName)):
                continue
            pairs.append([pcapFileName, harFileName])

    return pairs

def do_analyse(dump_file, har_file, key_file):
    finalHarFile = har_file.split('.har')[0]+'_final.har'
    cmd = ANALYSE_CMD.format(pcapfile=dump_file, keyfile=key_file, harfile=har_file,finalhar=finalHarFile)
    # WARNING: security risk: shell=True
    p = subprocess.Popen(cmd, shell=True)
    rc = p.wait()
    if rc == 0:
        return finalHarFile
    else:
        return None

def run_analyse(response):
    if response['status'] != 0:
        # bad test
        return response
    workingDir = response['_job-path']
    configFile = os.path.join(workingDir, 'tests.json')
    if not os.path.isfile(configFile):
        response['config-file-missing'] = configFile
        return
    keyFile = os.path.join(workingDir, 'ssl_keylog')
    if not os.path.isfile(keyFile):
        # It is OK not to have a keyfile
        response['config-file-missing'] = keyFile
        keyFile = ''
    pairs = find_dump_har_pairs(workingDir, configFile)
    finalHars = []
    for pair in pairs:
        finalHars.append(do_analyse(pair[0], pair[1], keyFile))
    response['final-hars'] = finalHars
    return response

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
    elif body['action'] == 'run-test-and-analyse':
        response = run_test(body)
        return run_analyse(response)
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
