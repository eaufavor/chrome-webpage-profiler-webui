#!/usr/bin/env python
#http://www.acmesystems.it/python_httpd
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from SocketServer import ThreadingMixIn
import threading, Queue
import json, subprocess, os, time, urlparse, re, argparse, socket, datetime

HELLO_MESSAGE = {'message':'hello, please use JSON via POST!'}
ERROR_JSON_MESSAGE = {'message':'POST content type must be application/json!'}
ERROR_BADJSON_MESSAGE = {'message':'POST content must be valid json!'}
ERROR_BADPASS_MESSAGE = {'message':'Wrong secret key!'}
ERROR_CMDERROR_MESSAGE = {'message':'Bad command!'}

ACTIONS = {'run-test', 'self-test', 'run-test-and-analyze'}


# TODO: dryrun to test these paths
os.chdir(os.path.abspath(os.path.dirname(__file__)))
TMP = os.path.abspath(r'./tmp')
TEST_DRIVER = os.path.abspath(r'../../chrome-webpage-profiler/test_driver.py')
H2_ANALYZER = os.path.abspath(r'../../http2-dump-anatomy/http_traffic_analyzer.py')
MERGE_TOOL = os.path.abspath(r'../../http2-dump-anatomy/merge_har.py')
TSHARK = os.path.abspath(r'../../wireshark-1.99.7/tshark')

PIDFILE = os.path.abspath(r'./chrome-webpage-profiler-agent.pid')

ANALYZE_CMD = '{H2_ANALYZER} -g {{pcapfile}} -k {{keyfile}} -b {TSHARK} | {MERGE_TOOL} {{harfile}} -o {{finalhar}}'
ANALYZE_CMD = ANALYZE_CMD.format(H2_ANALYZER=H2_ANALYZER, TSHARK=TSHARK, MERGE_TOOL=MERGE_TOOL)
#TEST_DRIVER = os.path.abspath(r'/bin/cat')

# NOTE: the key is to avoid unintentional access, not to secure the agent
SECRET_KEY = '1a2b'


TEST_WORKERS = {}
ANALYZE_WORKERS = {}

MAX_TEST_JOBS = 1

testQueue = Queue.Queue(1)
anaylzeQueue = Queue.Queue()


### the following two helper fuctions are from chrome-webpage-profiler
### NOTE: remmember to sync them if those are updated
### SYNC START
def _sanitize_url(url):
    '''Returns a version of the URL suitable for use in a file name.'''
    return re.sub(r'[/\;,><&*:%=+@!#^()|?^]', '-', url)

def _outfile_path(working_dir, url, suffix=None, trial=None):
    '''Returns a path for an output file (e.g., HAR, screenshot, pcap)'''
    filename = _sanitize_url(url)
    if trial is not None:
        filename += '_%d' % trial
    if suffix:
        filename += suffix
    return os.path.join(working_dir, filename)
### SYNC END

### Helper functions

def jobId_to_jobIdIndex(jobId):
    return jobId[-10:-5]

def find_dump_har_pairs(working_dir, config_file):
    pairs = []
    with open(config_file, 'r') as f:
        config = json.load(f)

    for test in config['tests']:
        pcapFileNamePrefix = test.get('packet_capture_file_name', test['url'])
        harFileNamePrefix = test.get('har_file_name', test['url'])
        with open(os.path.join(working_dir, 'analyze.log'), 'a') as log:
            for i in range(0, test.get('num_trials', 1)):
                pcapFileName = _outfile_path(working_dir, pcapFileNamePrefix, suffix='.pcap', trial=i)
                harFileName = _outfile_path(working_dir, harFileNamePrefix, suffix='.har', trial=i)
                if not os.path.isfile(pcapFileName):
                    log.write('Analyze warning: missing %s\n'% pcapFileName)
                    continue
                if not os.path.isfile(harFileName):
                    log.write('Analyze warning: missing %s\n'% harFileName)
                    continue
                pairs.append([pcapFileName, harFileName])
    return pairs
### Helper functions end

### Worker functions for async process
def test_worker(worker_id, queue, analyze_queue):
    while True:
        testJob = queue.get()
        TEST_WORKERS[worker_id] = testJob['jobId']
        response = run_test_body(testJob['testConfig'], testJob['jobIdPath'],
                           testJob['jobIdIndex'], testJob['jobId'])
        TEST_WORKERS[worker_id] = None
        if testJob['willAnalyze']:
            analyze_queue.put(response)
        else:
            p = subprocess.Popen(['touch', '.ALL_DONE'], cwd=testJob['jobIdPath'])
            p.wait()
        queue.task_done()

def analyze_worker(worker_id, queue):
    while True:
        analyzeJob = queue.get()
        ANALYZE_WORKERS[worker_id] = analyzeJob['job-id']
        run_analyze(analyzeJob)
        p = subprocess.Popen(['touch', '.ALL_DONE'], cwd=analyzeJob['_job-path'])
        p.wait()
        queue.task_done()
### async functions end

### functions for running test drivers
def run_test(body, willAnalyze=False, async=False):

    if not body.get('tests-config'):
        return {'message': ERROR_CMDERROR_MESSAGE}

    if not os.path.isdir(TMP):
        try:
            os.makedirs(TMP)
        except Exception as _:
            msg = 'Error making output directory: %s', TMP
            return {'message': msg, 'status': -1}
    if not os.path.isfile(TEST_DRIVER):
        msg = 'No test driver found at %s' % TEST_DRIVER
        return {'message': msg, 'status': -1}

    jobId = "%d"%(time.time()*1000)
    jobIdIndex = jobId_to_jobIdIndex(jobId)
    jobIdIndexPath = os.path.join(TMP, jobIdIndex)
    jobIdPath = os.path.join(jobIdIndexPath, jobId)
    testConfig = os.path.join(jobIdPath, 'tests.json')

    if not os.path.isdir(jobIdIndexPath):
        try:
            os.makedirs(jobIdIndexPath)
        except Exception as _:
            msg = 'Error making output directory: %s', jobIdIndexPath
            return {'message': msg, 'status': -2}

    if not os.path.isdir(jobIdPath):
        try:
            os.makedirs(jobIdPath)
        except Exception as _:
            msg = 'Error making output directory: %s', jobIdPath
            return {'message': msg, 'status': -2}

    tests = body['tests-config']
    with open(testConfig, 'w') as outfile:
        json.dump(tests, outfile, indent=4)

    if not async:
        response = run_test_body(testConfig, jobIdPath, jobIdIndex, jobId)
        if willAnalyze:
            return run_analyze(response)
        else:
            return response
    else:
        if testQueue.unfinished_tasks >= MAX_TEST_JOBS:
            return {'message': 'Test queue is full. %d tasks'%testQueue.unfinished_tasks, 'status': -2}
        job = {}
        job['testConfig'] = testConfig
        job['jobIdPath'] = jobIdPath
        job['jobIdIndex'] = jobIdIndex
        job['jobId'] = jobId
        job['willAnalyze'] = willAnalyze
        testQueue.put(job)
        response = {'message': 'OK. Job runing', 'job-id': jobId}
        return response

def run_test_body(testConfig, jobIdPath, jobIdIndex, jobId):
    with open (os.path.join(jobIdPath, 'test.log'), 'w+') as testLog:
        p = subprocess.Popen([TEST_DRIVER, testConfig], cwd=jobIdPath,
                             stdout=testLog, stderr=testLog)
        rc = p.wait()
    if rc == 0:
        jobUrl = os.path.join('/tmp/', jobIdIndex, jobId)
        response = {'message': 'OK. Done', 'job-id': jobId,
                    'status': rc, '_job-path': jobIdPath, '_job-url': jobUrl}
        response['files'] = []
        for f in os.listdir(jobIdPath):
            response['files'].append(os.path.join(jobUrl, f))
        with open(os.path.join(jobIdPath, 'test.log'), 'a') as log:
            p = subprocess.Popen(['touch', '.TEST_DONE'], cwd=jobIdPath,
                                 stdout=log, stderr=log)
        p.wait()
        with open(os.path.join(jobIdPath, '.TEST_RESPONSE'), 'w') as responseFile:
            json.dump(response, responseFile, indent=4)
        with open(os.path.join(jobIdPath, '.RESPONSE'), 'w') as responseFile:
            json.dump(response, responseFile, indent=4)
        return response
    else:
        with open(os.path.join(jobIdPath, 'test.log'), 'a') as log:
            log.write('Tests failed :%d\n'% rc)
        p = subprocess.Popen(['touch', '.TEST_FAILED'], cwd=jobIdPath,
                             stdout=testLog, stderr=testLog)
        p.wait()
        return {'message': 'FAIL. return code%d'%rc, 'status': rc}
### Test driver ends

### Functions for analyzer tools
def run_analyze(response):
    workingDir = response['_job-path']
    with open(os.path.join(workingDir, 'anaylyze.log'), 'a') as log:
        if response['status'] != 0:
            # bad test
            log.write('Giving up analyze because tests(%d) failed: %d\n' %
                             (response['job-id'], response['status']))
            return response
        configFile = os.path.join(workingDir, 'tests.json')
        if not os.path.isfile(configFile):
            log.write('Analyze failed: config-file-missing: %s' % configFile)
            response['_config-file-missing'] = configFile
            with open(os.path.join(workingDir, '.RESPONSE'), 'w') as responseFile:
                json.dump(response, responseFile, indent=4)
            p = subprocess.Popen(['touch', '.ANALYZE_FAILED'], cwd=workingDir)
            p.wait()
            return response
        keyFile = os.path.join(workingDir, 'ssl_keylog')
        if not os.path.isfile(keyFile):
            # It is OK not to have a keyfile
            log.write('Analyze warning: key-file-missing: %s' % configFile)
            response['_key-file-missing'] = keyFile
            keyFile = ''
    pairs = find_dump_har_pairs(workingDir, configFile)
    finalHars = []
    for pair in pairs:
        finalHars.append(do_analyze(pair[0], pair[1], keyFile))
    response['final-hars'] = finalHars
    response['files'].append(os.path.join(response['_job-url'], 'analyze.log'))
    with open(os.path.join(workingDir, '.RESPONSE'), 'w') as responseFile:
        json.dump(response, responseFile, indent=4)
    p = subprocess.Popen(['touch', '.ANALYZE_DONE'], cwd=workingDir)
    p.wait()
    return response

def do_analyze(dump_file, har_file, key_file):
    finalHarFile = har_file.split('.har')[0]+'_final.har'
    cmd = ANALYZE_CMD.format(pcapfile=dump_file, keyfile=key_file, harfile=har_file,finalhar=finalHarFile)
    jobIdPath = os.path.dirname(dump_file)
    with open(os.path.join(jobIdPath, 'anaylyze.log'), 'a') as log:
        log.write('Analyze running: %s\n' % cmd)
    with open (os.path.join(jobIdPath, 'analyze.log'), 'a+') as analyzeLog:
        # WARNING: security risk: shell=True
        p = subprocess.Popen(cmd, shell=True, stdout=analyzeLog, stderr=analyzeLog)
        rc = p.wait()
    if rc == 0:
        # fix path: abs file path to url path
        return '/tmp' + finalHarFile.split('/tmp')[1]
    else:
        with open(os.path.join(jobIdPath, 'anaylyze.log'), 'a') as log:
            log.write('Analyze cmd failed: %d\n' % rc)
        return None
### Analyzer tool ends

### self test functions
def self_test(instance):
    response = {'message': 'self test done', 'results': {} }
    #rc = subprocess.check_output('df -h; exit 0', stderr=subprocess.STDOUT, shell=True)
    response['results']['client'] = instance.client_address
    workers = []
    for w in instance.server.threads:
        workers.append(w.getName())
    response['results']['worker_threads'] = workers
    response['results']['unfinished_tests'] = testQueue.unfinished_tasks
    response['results']['unfinished_analyse'] = anaylzeQueue.unfinished_tasks

    return response

def async_dryrun(_):
    pass

### self test functions end

class S(BaseHTTPRequestHandler):

    ### trivial services
    def _set_headers(self, mime_type='application/json'):
        self.send_response(200)
        self.send_header('Content-type', mime_type)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

    def send_file(self):
        request = urlparse.urlparse(self.path)
        query = urlparse.parse_qs(request.query)
        makeJsonp = False

        if request.path.endswith(".json") or request.path.endswith(".har"):
            mimeType = 'application/json'
        elif request.path.endswith(".jsonp") or request.path.endswith(".harp"):
            # callable types
            mimeType = 'application/javascript'
            makeJsonp = True
        elif request.path.endswith(".pcap"):
            mimeType = 'application/octet-stream'
        else:
            # the ssl_keylog, and .log file
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
            callback = query.get('callback', ['callback'])[0]
            response_body = '{0}({1});'.format(callback, f.read())
            self.wfile.write(response_body)
        else:
            self.wfile.write(f.read())

    def get_to_post_Jsonp(self):
        #convert GET to POST
        #AKA put query string in fake body
        request = urlparse.urlparse(self.path)
        query = urlparse.parse_qs(request.query)
        callback = query.get('callback', ['callback'])[0]
        body = {}
        body['action'] = query.get('action', [None])[0]
        body['key'] = query.get('key', [None])[0]
        body['tests-config'] = query.get('tests-config', [None])[0]
        body = json.dumps(body)
        response_body =  json.dumps(self.execute_POST(body), indent=4)
        response_body = '{0}({1});'.format(callback, response_body)
        self.wfile.write(response_body)

    def get_status(self):
        request = urlparse.urlparse(self.path)
        query = urlparse.parse_qs(request.query)
        callback = query.get('callback', [])
        if not callback:
            callback = 'callback'
        else:
            callback = callback[0]
        reply = {'message':'%s \n Chrome webpage profiler web agent is alive at %s.' %\
                        (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), socket.gethostname())}
        response_body = '{0}({1});'.format(callback, json.dumps(reply, indent=4))
        self.wfile.write(response_body)
    ### trivial services end

    ### HTTP url router functions
    def execute_POST(self, body, async=False):
        try:
            body = json.loads(body)
        except ValueError as _:
            return ERROR_BADJSON_MESSAGE

        if body.get('key') != SECRET_KEY:
            return ERROR_BADPASS_MESSAGE

        if body.get('action') not in ACTIONS:
            return ERROR_CMDERROR_MESSAGE

        if body['action'] == 'run-test':
            return run_test(body, async=async)
        elif body['action'] == 'dryrun':
            return async_dryrun(body)
        elif body['action'] == 'run-test-and-analyze':
            return run_test(body, willAnalyze=True, async=async)
        elif body['action'] == 'self-test':
            return self_test(self)

    def do_GET(self):
        request = urlparse.urlparse(self.path)

        if request.path.startswith('/tmp'):
            self.send_file()
        elif request.path == ('/status'):
            self.get_status()
        elif request.path == ('/run'):
            self.get_to_post_Jsonp()
        else:
            self.send_error(403,'Should not access: %s' % request.path)
            return

        return

    def do_HEAD(self):
        self.send_error(501, 'Do not support HEAD')

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_POST(self):
        request = urlparse.urlparse(self.path)
        if request.path == ('/run'):
            query = urlparse.parse_qs(request.query)
            callback = query.get('callback', ['callback'])[0]
            makeJsonp = True
            self._set_headers("application/javascript")
        else:
            makeJsonp = False
            self._set_headers()

        async = True if request.path == ('/async') else False

        content_len = int(self.headers.getheader('content-length', 0))
        content_type = self.headers.getheader('content-type', 0)
        if content_type.lower() != 'application/json' and \
           content_type.lower() != 'application/x-www-form-urlencoded; charset=UTF-8'.lower():
            response_body = json.dumps(ERROR_JSON_MESSAGE, indent=4)
        else:
            post_body = self.rfile.read(content_len)
            response_body =  json.dumps(self.execute_POST(post_body, async=async), indent=4)
        if makeJsonp:
            response_body = '{0}({1});'.format(callback, response_body)
        self.wfile.write(response_body)
    ### router function ends

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

    def __init__(self, server_address, handler_class):
        HTTPServer.__init__(self, server_address, handler_class)
        self.threads = []

    def start_workers(self):
        t_worker = threading.Thread(name='test_worker0', target=test_worker, args=('test_worker0', testQueue, anaylzeQueue))
        a_worker = threading.Thread(name='analyze_worker0', target=analyze_worker, args=('analyze_worker0', anaylzeQueue))
        self.threads.append(t_worker)
        self.threads.append(a_worker)

        for worker in self.threads:
            worker.daemon = True
            print 'Starting worker', worker.getName()
            worker.start()

def run(server_class=ThreadedHTTPServer, handler_class=S, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print 'Starting httpd...'
    httpd.start_workers()
    httpd.serve_forever()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                                     description='Web agent for Chrome webpage profiler suite')
    parser.add_argument('-p', '--port',type=int, default=8000, help='the TCP port number the agent listens')
    parser.add_argument('-d', '--daemon', action='store_true', default=False, help='run the agent as a daemon')
    parser.add_argument('-k', '--kill', action='store_true', default=False, help='kill a running daemon')
    args = parser.parse_args()
    if args.daemon:
        import daemon, daemon.pidfile, sys
        pidFile = daemon.pidfile.PIDLockFile(PIDFILE)
        pid = pidFile.read_pid()
        if pid is not None:
            print "Another agent daemon, PID %d, is running. Quit." % pid
            sys.exit(-1)
        agentLog = open('agent.log', 'a+')
        context = daemon.DaemonContext(stdout=agentLog,
                                       stderr=agentLog,
                                       pidfile=pidFile)
        context.files_preserve = [agentLog]
        with context:
            print "Starting Daemon on port %d" %  args.port
            run(port=args.port)
    elif args.kill:
        import signal, daemon, daemon.pidfile, sys
        pidFile = daemon.pidfile.PIDLockFile(PIDFILE)
        pid = pidFile.read_pid()
        if pid is None:
            print "No agent daemon found."
            sys.exit(-1)
        else:
            os.kill(int(pid), signal.SIGTERM)
            print "PID %d killed" % pid

    else:
        run(port=args.port)
