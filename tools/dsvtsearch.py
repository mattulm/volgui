#!/usr/bin/env python

__description__ = 'Program to search VirusTotal reports with search terms (MD5, SHA1, SHA256) found in the argument file'
__author__ = 'Didier Stevens'
__version__ = '0.1.0'
__date__ = '2013/11/27'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2012/04/25: start
  2012/04/27: added serialization of reports
  2012/05/23: emergency fix pkl init bug
  2012/05/26: 0.0.3 added force option and key option; added environment variable; added requested field
  2012/12/17: 0.0.4 added proxy and option insecure
  2013/02/22: 0.0.5 added InsecureJSONParsing
  2013/03/15: 0.0.6 added json; removed option insecure and InsecureJSONParsing
  2013/04/19: 0.0.7 refactoring; proxies
  2013/04/29: 0.0.8 added option globaldb
  2013/06/10: 0.0.9 fixed bug for print None with CN, thanks Mark Woan
  2013/06/17: added exception handling for jsonalias.loads
  2013/11/26: 0.1.0 update to perform up to 4 searchs per request
  2013/11/27: bugfix pkl

Todo:
"""

import optparse
import urllib
import urllib2
import time
import sys
import pickle
import os
import traceback

try:
    import json
    jsonalias = json
except:
    try:
        import simplejson
        jsonalias = simplejson
    except:
        print('Modules json and simplejson missing')
        exit()

VIRUSTOTAL_API2_KEY = ''
HTTP_PROXY = ''
HTTPS_PROXY = ''

VIRUSTOTAL_REPORT_URL = "https://www.virustotal.com/vtapi/v2/file/report"

PICKLE_FILE = 'virustotal-search.pkl'

#CN = ConvertNone
def CN(value, stringNone=''):
    if value == None:
        return stringNone
    else:
        return value

def Serialize(filename, object):
    try:
        fPickle = open(filename, 'wb')
    except:
        return False
    try:
        pickle.dump(object, fPickle)
    except:
        return False
    finally:
        fPickle.close()
    return True

def DeSerialize(filename):
    import os.path

    if os.path.isfile(filename):
        try:
            fPickle = open(filename, 'rb')
        except:
            return None
        try:
            object = pickle.load(fPickle)
        except:
            return None
        finally:
            fPickle.close()
        return object
    else:
        return None

def Timestamp(epoch=None):
    if epoch == None:
        localTime = time.localtime()
    else:
        localTime = time.localtime(epoch)
    return '%04d%02d%02d-%02d%02d%02d' % localTime[0:6]

class CSVLogger():
    def __init__(self, prefix, headers, separator=';'):
        self.separator = separator
        self.filename = '%s-%s.csv' % (prefix, Timestamp())
        self.f = open(self.filename, 'w')
        self.f.write(self.separator.join(headers) + '\n')
        self.f.close()

    def PrintAndLog(self, formats, parameters):
        line = self.separator.join(formats) % parameters
        print(line)
        f = open(self.filename, 'a')
        f.write(line + '\n')
        f.close()

def VTHTTPReportRequest(searchTerm):
    global VIRUSTOTAL_API2_KEY

    req = urllib2.Request(VIRUSTOTAL_REPORT_URL, urllib.urlencode({'resource': searchTerm, 'apikey': VIRUSTOTAL_API2_KEY}))
    try:
        if sys.hexversion >= 0x020601F0:
            hRequest = urllib2.urlopen(req, timeout=15)
        else:
            hRequest = urllib2.urlopen(req)
    except:
        return None
    try:
        data = hRequest.read()
    except:
        return None
    finally:
        hRequest.close()
    return data

def InsertIntoTuple(tupleIn, position, value):
    listIn = list(tupleIn)
    listIn.insert(position, value)
    return tuple(listIn)

def ParseSearchterm(searchTerm, withComment):
    comment = None
    if withComment:
        index = searchTerm.find(' ')
        if index == -1:
            comment = ''
        else:
            try:
                comment = searchTerm[index + 1:]
            except:
                comment = ''
            searchTerm = searchTerm[:index]
    return (searchTerm, comment)

def LogResult(searchTerm, comment, oResult, issuedRequest, withComment):
    global oLogger

    if oResult['response_code'] == 1:
        scans = []
        for scan in sorted(oResult['scans']):
            if oResult['scans'][scan]['detected']:
                scans.append('#'.join(map(CN, (scan, oResult['scans'][scan]['result'], oResult['scans'][scan]['update'], oResult['scans'][scan]['version']))))
        formats = ('%s', '%d', '%d', '%s', '%d', '%d', '%s', '%s')
        parameters = (searchTerm, issuedRequest, oResult['response_code'], oResult['scan_date'], oResult['positives'], oResult['total'], oResult['permalink'], ','.join(scans))
        if withComment:
            formats = InsertIntoTuple(formats, 1, '%s')
            parameters = InsertIntoTuple(parameters, 1, comment)
        oLogger.PrintAndLog(formats, parameters)
    else:
        formats = ('%s', '%d', '%d', '%s')
        parameters = (searchTerm, issuedRequest, oResult['response_code'], oResult['verbose_msg'])
        if withComment:
            formats = InsertIntoTuple(formats, 1, '%s')
            parameters = InsertIntoTuple(parameters, 1, comment)
        oLogger.PrintAndLog(formats, parameters)

def GetReports(searchTerms, reports, withComment):
    global oLogger

    searchTermComments = [ParseSearchterm(searchTerm, withComment) for searchTerm in searchTerms]

    searchTerm = ','.join([searchTermComment[0] for searchTermComment in searchTermComments])
    jsonResponse = VTHTTPReportRequest(searchTerm)
    if jsonResponse == None:
        formats = ('%s', '%s')
        parameters = (searchTerm, 'Error VTHTTPReportRequest')
        if withComment:
            formats = InsertIntoTuple(formats, 1, '%s')
            parameters = InsertIntoTuple(parameters, 1, comment)
        oLogger.PrintAndLog(formats, parameters)
        return

    try:
        if len(searchTerms) == 1:
            oResults = [jsonalias.loads(jsonResponse)]
        else:
            oResults = jsonalias.loads(jsonResponse)
    except:
        formats = ('%s', '%s', '%s', '%s')
        parameters = (searchTerm, 'Error jsonalias.loads', sys.exc_info()[1], repr(traceback.format_exc()))
        if withComment:
            formats = InsertIntoTuple(formats, 1, '%s')
            parameters = InsertIntoTuple(parameters, 1, comment)
        oLogger.PrintAndLog(formats, parameters)
        return

    for iIter in range(len(searchTerms)):
        if oResults[iIter]['response_code'] == 1:
            reports[searchTermComments[iIter][0]] = oResults[iIter]
        LogResult(searchTermComments[iIter][0], searchTermComments[iIter][1], oResults[iIter], True, withComment)

def File2Strings(filename):
    try:
        f = open(filename, 'r')
    except:
        return None
    try:
        return map(lambda line:line.rstrip('\n'), f.readlines())
    except:
        return None
    finally:
        f.close()

def SetProxiesIfNecessary():
    global HTTP_PROXY
    global HTTPS_PROXY

    dProxies = {}
    if HTTP_PROXY != '':
        dProxies['http'] = HTTP_PROXY
    if HTTPS_PROXY != '':
        dProxies['https'] = HTTPS_PROXY
    if os.getenv('http_proxy') != None:
        dProxies['http'] = os.getenv('http_proxy')
    if os.getenv('https_proxy') != None:
        dProxies['https'] = os.getenv('https_proxy')
    if dProxies != {}:
        urllib2.install_opener(urllib2.build_opener(urllib2.ProxyHandler(dProxies)))

def GetPickleFile(globaldb):
    if globaldb:
        return os.path.join(os.path.dirname(sys.argv[0]), PICKLE_FILE)
    else:
        return PICKLE_FILE

def VirusTotalSearch(filename, options):
    global oLogger

    SetProxiesIfNecessary()

    searchTerms = File2Strings(filename)
    if searchTerms == None:
        print('Error reading file %s' % filename)
        return
    elif searchTerms == []:
        print('No searchterms in file %s' % filename)
        return

    headers = ('Search Term', 'Requested', 'Response', 'Scan Date', 'Detections', 'Total', 'Permalink', 'AVs')
    if options.comment:
        headers = InsertIntoTuple(headers, 1, 'Comment')
    oLogger = CSVLogger('virustotal-search', headers)

    data = DeSerialize(GetPickleFile(options.globaldb))
    if data == None:
        reports = {}
    else:
        reports = data['reports']

    searchTermsToRequest = []
    if options.force:
        searchTermsToRequest = searchTerms
    else:
        for searchTermIter in searchTerms:
            searchTerm, comment = ParseSearchterm(searchTermIter, options.comment)
            if searchTerm in reports:
                LogResult(searchTerm, comment, reports[searchTerm], False, options.comment)
            else:
                searchTermsToRequest.append(searchTermIter)

    while searchTermsToRequest != []:
        GetReports(searchTermsToRequest[0:4], reports, options.comment)
        searchTermsToRequest = searchTermsToRequest[4:]
        if searchTermsToRequest != []:
            time.sleep(options.delay)
    Serialize(GetPickleFile(options.globaldb), {'reports': reports})

def Main():
    global VIRUSTOTAL_API2_KEY

    oParser = optparse.OptionParser(usage='usage: %prog [options] file\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-d', '--delay', type=int, default=16, help='delay in seconds between queries (default 16s, VT rate limit is 4 queries per minute)')
    oParser.add_option('-c', '--comment', action='store_true', default=False, help='the search term is followed by a comment and separated by a space character')
    oParser.add_option('-f', '--force', action='store_true', default=False, help='force all request to be send to VirusTotal, even if found in local database (pkl file)')
    oParser.add_option('-k', '--key', default='', help='VirusTotal API key')
    oParser.add_option('-g', '--globaldb', action='store_true', default=False, help='use global database (pkl file) in same directory as program')
    (options, args) = oParser.parse_args()

    if len(args) != 1:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return
    if os.getenv('VIRUSTOTAL_API2_KEY') != None:
        VIRUSTOTAL_API2_KEY = os.getenv('VIRUSTOTAL_API2_KEY')
    if options.key != '':
        VIRUSTOTAL_API2_KEY = options.key
    if VIRUSTOTAL_API2_KEY == '':
        print('You need to get a VirusTotal API key and set environment variable VIRUSTOTAL_API2_KEY, use option -k or add it to this program.\nTo get your API key, you need a VirusTotal account.')
    else:
        VirusTotalSearch(args[0], options)

if __name__ == '__main__':
    Main()
