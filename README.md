# chrome-webpage-profiler-webui
The network based UI of chrome webpage profiler

#Agent

Agent is a server side implemetation of the RESTful APIs to remotely control chrome webpage profiler.
```
usage: agent.py [-h] [-p PORT] [-d] [-k]

Web agent for Chrome webpage profiler suite

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  the TCP port number the agent listens (default: 8000)
  -d, --daemon          run the agent as a daemon (default: False)
  -k, --kill            kill a running daemon (default: False)
```

#Webclient

Web client is a simple web page based client side interface using the APIs

#Test

Test directory contains the CLI client interface For the APIs and examples of it.

```
usage: remote_test.py [-h] [-n] [-a] [-w] [-z] [-r] [-f] [-p] [-v]
                      agent config

A handy tool to perform remote test and retrieve result files

positional arguments:
  agent           IPaddress:PORT of agent, no "http"
  config          Path to the config file, or Job ID in retrieve mode

optional arguments:
  -h, --help      show this help message and exit
  -n, --noresult  don not try to download result file at all, only show
                  response (default: False)
  -a, --async     async mode, POST and leave (default: False)
  -w, --wait      poll and wait until job is done in async mode (default:
                  False)
  -z, --tarball   download tarball instead of files (default: False)
  -r, --retrieve  retrieve the results using job ID (default: False)
  -f, --final     only download the final har (default: False)
  -p, --harp      just print out the urls of the final har in jsonp format
                  (default: False)
  -v, --verbose   Print more (default: False)
```

