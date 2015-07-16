#!/usr/bin/env python
#http://www.acmesystems.it/python_httpd
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
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

ANALYSE_CMD = '{H2_ANALYZER} -g {{pcapfile}} -k {{keyfile}} -b {TSHARK} | {MERGE_TOOL} {{harfile}} -o {{finalhar}}'
ANALYSE_CMD = ANALYSE_CMD.format(H2_ANALYZER=H2_ANALYZER, TSHARK=TSHARK, MERGE_TOOL=MERGE_TOOL)
#TEST_DRIVER = os.path.abspath(r'/bin/cat')

# NOTE: the key is to avoid unintentional access, not to secure the agent
SECRET_KEY = '1a2b'

class S(BaseHTTPRequestHandler):
    def run_test(self, body):

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
        jobIdIndex = jobId[-10:-5]
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
            return response
        else:
            self.log_message('Tests failed :%d', rc)
            return {'message': 'FAIL. return code%d'%rc, 'status': rc}

    ### the following two helper fuctions are from chrome-webpage-profiler
    ### NOTE: remmember to sync them if those are updated
    ### SYNC START
    def _sanitize_url(self, url):
        '''Returns a version of the URL suitable for use in a file name.'''
        return re.sub(r'[/\;,><&*:%=+@!#^()|?^]', '-', url)

    def _outfile_path(self, working_dir, url, suffix=None, trial=None):
        '''Returns a path for an output file (e.g., HAR, screenshot, pcap)'''
        filename = self._sanitize_url(url)
        if trial is not None:
            filename += '_%d' % trial
        if suffix:
            filename += suffix
        return os.path.join(working_dir, filename)
    ### SYNC END

    def find_dump_har_pairs(self, working_dir, config_file):
        pairs = []
        with open(config_file, 'r') as f:
            config = json.load(f)

        for test in config['tests']:
            pcapFileName = test.get('packet_capture_file_name', test['url'])
            harFileName = test.get('har_file_name', test['url'])
            for i in range(0, test.get('num_trials', 1)):
                pcapFileName = self._outfile_path(working_dir, pcapFileName, suffix='.pcap', trial=i)
                harFileName = self._outfile_path(working_dir, harFileName, suffix='.har', trial=i)
                if not os.path.isfile(pcapFileName):
                    self.log_message('Analyse warning: missing %s', pcapFileName)
                    continue
                if not os.path.isfile(harFileName):
                    self.log_message('Analyse warning: missing %s', harFileName)
                    continue
                pairs.append([pcapFileName, harFileName])

        return pairs

    def do_analyse(self, dump_file, har_file, key_file):
        finalHarFile = har_file.split('.har')[0]+'_final.har'
        cmd = ANALYSE_CMD.format(pcapfile=dump_file, keyfile=key_file, harfile=har_file,finalhar=finalHarFile)
        self.log_message('Analyze running: %s', cmd)
        jobIdPath = os.path.dirname(dump_file)
        with open (os.path.join(jobIdPath, 'analyze.log'), 'a+') as analyzeLog:
            # WARNING: security risk: shell=True
            p = subprocess.Popen(cmd, shell=True, stdout=analyzeLog, stderr=analyzeLog)
            rc = p.wait()
        if rc == 0:
            # fix path: abs file path to url path
            return '/tmp' + finalHarFile.split('/tmp')[1]
        else:
            self.log_message('Analyse cmd failed: %d', rc)
            return None

    def run_analyse(self, response):
        if response['status'] != 0:
            # bad test
            self.log_message('Giving up analyse because tests(%d) failed: %d',
                             response['job-id'], response['status'])
            return response
        workingDir = response['_job-path']
        configFile = os.path.join(workingDir, 'tests.json')
        if not os.path.isfile(configFile):
            self.log_message('Analyse failed: config-file-missing: %s', configFile)
            response['_config-file-missing'] = configFile
            return
        keyFile = os.path.join(workingDir, 'ssl_keylog')
        if not os.path.isfile(keyFile):
            # It is OK not to have a keyfile
            self.log_message('Analyse warning: key-file-missing: %s', configFile)
            response['_key-file-missing'] = keyFile
            keyFile = ''
        pairs = self.find_dump_har_pairs(workingDir, configFile)
        finalHars = []
        for pair in pairs:
            finalHars.append(self.do_analyse(pair[0], pair[1], keyFile))
        response['final-hars'] = finalHars
        response['files'].append(os.path.join(response['_job-url'], 'analyze.log'))
        return response

    def self_test(self):
        response = {'message': 'self test done', 'results': {} }
        rc = subprocess.check_output('df -h; exit 0', stderr=subprocess.STDOUT, shell=True)
        response['results']['df'] = rc

        return response


    def execute_POST(self, body):
        try:
            body = json.loads(body)
        except ValueError as _:
            return ERROR_BADJSON_MESSAGE

        if body.get('key') != SECRET_KEY:
            return ERROR_BADPASS_MESSAGE

        if body.get('action') not in ACTIONS:
            return ERROR_CMDERROR_MESSAGE

        if body['action'] == 'run-test':
            return self.run_test(body)
        elif body['action'] == 'run-test-and-analyze':
            response = self.run_test(body)
            return self.run_analyse(response)
        elif body['action'] == 'self-test':
            return self.self_test()


    def _set_headers(self, mime_type='application/json'):
        self.send_response(200)
        self.send_header('Content-type', mime_type)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

    def send_files(self):
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

    def do_GET(self):
        request = urlparse.urlparse(self.path)

        if request.path.startswith('/tmp'):
            self.send_files()
        elif request.path == ('/status'):
            self.get_status()
        elif request.path == ('/run'):
            self.run_Jsonp()
        else:
            self.send_error(403,'Should not access: %s' % request.path)
            return

        return

    def do_HEAD(self):
        self.send_error(501, 'Do not support HEAD')

    def run_Jsonp(self):
        request = urlparse.urlparse(self.path)
        query = urlparse.parse_qs(request.query)
        callback = query.get('callback', ['callback'])[0]
        body = {}
        body['action'] = query.get('action', [None])[0]
        body['key'] = query.get('key', [None])[0]
        body['tests-config'] = query.get('tests-config', [None])[0]
        print body
        body = json.dumps(body)
        response_body =  json.dumps(self.execute_POST(body), indent=4)
        response_body = '{0}({1});'.format(callback, response_body)
        self.wfile.write(response_body)

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
        content_len = int(self.headers.getheader('content-length', 0))
        content_type = self.headers.getheader('content-type', 0)
        if content_type.lower() != 'application/json' and \
           content_type.lower() != 'application/x-www-form-urlencoded; charset=UTF-8'.lower():
            response_body = json.dumps(ERROR_JSON_MESSAGE, indent=4)
        else:
            post_body = self.rfile.read(content_len)
            response_body =  json.dumps(self.execute_POST(post_body), indent=4)
        if makeJsonp:
            response_body = '{0}({1});'.format(callback, response_body)
        self.wfile.write(response_body)

def run(server_class=HTTPServer, handler_class=S, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print 'Starting httpd...'
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
