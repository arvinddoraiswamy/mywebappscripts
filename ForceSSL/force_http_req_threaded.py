#http://stackoverflow.com/questions/110498/is-there-an-easy-way-to-request-a-url-in-python-and-not-follow-redirects
#http://kentsjohnson.com/kk/00010.html
#http://stackoverflow.com/questions/4560288/python-try-except-showing-the-cause-of-the-error-after-displaying-my-variables
#http://nocivus.posterous.com/way-to-wait-for-all-threads-to

import sys
import re
import urllib2
import traceback
import threading
import os
import time

urldir='URLs/'; requests='https_urls'; report='report'
urls_accessible_http=[]

def main():
  #The number of URLs you initially copy can be huge. This results in too many threads spawning and the stupid code crashing :). So we split.
  split_into_multiple_files()
  #Run code for every file in the directory.
  all_requests=os.listdir(urldir)
  for i in all_requests:
    #Does not start with a new file; unless all the threads processing the previous file are done.
    while threading.activeCount() > 1:
      time.sleep(0.01)
    print 'Processing file '+i
    #Uses simple regex to convert all the https URLs into http
    list_of_requests=read_https_urls(urldir+i)
    #Request every URL over HTTP
    request_over_http(list_of_requests)
    #This sleep is super important; as funny race conditions occur without it. May look at a better way later; for now this will do :)
    time.sleep(10)
    #Writes report to file
    create_report(i,urls_accessible_http)
    #Multiple instances written to file for some stupid reason; got to extract unique URLs only
    get_unique_urls(report)

#Uses Linux system commands to split. Is there a more 'platform independent' way of doing this? Probably.
def split_into_multiple_files():
  os.system('rm '+urldir+'*')
  os.system('cp '+requests+' '+urldir)
  os.system('split -l 50 '+urldir+requests+' url_')
  os.system('mv url_* URLs/')
  os.system('rm '+urldir+requests)
  os.system('rm '+report)
  
#Read BURP site map HTTPS Urls
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

#Request all converted URLs over HTTP
def request_over_http(list_of_requests):
  threads=[]
  #This is each split file getting read. Some nice threading done here :)
  for url in list_of_requests:
    url=re.sub(r'\s+$',r'',url)
    url=re.sub(r'^\s+',r'',url)
    t = threading.Thread(target=thread_request_over_http, args=(url,))
    threads.append(t)
    t.start()

  return urls_accessible_http

#Callback function for thread which does all the grunt work
def thread_request_over_http(url):
  try:
    f = urllib2.urlopen(url)
    t1=f.geturl().split(':')
    if t1[0] != 'https':
      urls_accessible_http.append(url)
  except Exception:
    pass

#Create a report after requests are made
def create_report(filename,urls_accessible_http):
  try:
    f=open(report,'a')
  except:
    print 'Cannot open file to write report'
    traceback.print_exc(file=sys.stdout)

  if len(urls_accessible_http) > 0:
    f.write(filename+'\n\n')
    for url in urls_accessible_http:
      f.write('-----------')
      f.write('\n'+url+'\n')
    f.write('-----------')
  else:
    f.write(filename+' --- None of the URLs can be accessed over HTTP.\n')

  f.close()

#Get only unique URLs from the report
def get_unique_urls(report):
  unique_urls=[]
  try:
    f=open(report,'rU')
  except:
    print 'Cannot open generated report'
  t1=f.read()
  f.close()

  t2=t1.split('\n')
  for i in t2:
    if i not in unique_urls:
      unique_urls.append(i)

  os.system('rm -rf '+report)
  try:
    f=open(report,'w')
  except:
    print 'Cannot write report with unique files'
  for i in unique_urls:
    if i != '':
      f.write(i+'\n') 
  f.close()

#Code starts here
main()
