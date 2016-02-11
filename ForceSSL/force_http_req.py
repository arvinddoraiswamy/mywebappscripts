#http://stackoverflow.com/questions/110498/is-there-an-easy-way-to-request-a-url-in-python-and-not-follow-redirects
#http://kentsjohnson.com/kk/00010.html
#http://stackoverflow.com/questions/4560288/python-try-except-showing-the-cause-of-the-error-after-displaying-my-variables

import sys
import re
import urllib2
import traceback
import threading
import time

requests='https_urls'; urls_accessible_http=[]

def main():
  list_of_requests=read_https_urls(requests)
  urls_accessible_http=request_over_http(list_of_requests)
  create_report(urls_accessible_http)

def create_report(urls_accessible_http):
  try:
    f=open('url_http_request_report','w')
  except:
    print 'Cannot open file to write report'
    traceback.print_exc(file=sys.stdout)

  if len(urls_accessible_http) > 0:
    for url in urls_accessible_http:
      f.write(url+'\n')
  else:
    f.write('None of the URLs can be accessed over HTTP.')

  f.close()

def read_https_urls(requests):
  list_of_requests=[]
  try:
    f=open(requests,'r')
  except:
    print 'Could not open file containing requests'
  for url in f:
    url=re.sub(r'^https',r'http',url)
    list_of_requests.append(url)
  f.close()
  return list_of_requests

def request_over_http(list_of_requests):
  threads=[]
  for url in list_of_requests:
    url=re.sub(r'\s+$',r'',url)
    url=re.sub(r'^\s+',r'',url)
    print 'Testing URL '+url
    try:
      f = urllib2.urlopen(url)
      t1=f.geturl().split(':')
      if t1[0] != 'https':
        urls_accessible_http.append(url)
    except Exception:
      pass

  time.sleep(5)
  return urls_accessible_http

main()
