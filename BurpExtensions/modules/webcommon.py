import re

def get_host_header_from_request(self,requestInfo):
  t1 = requestInfo.getHeaders()
  header_name='Host:'

  regex=re.compile('^.*%s.*'%header_name,re.IGNORECASE)
  for i in t1:
    #Search for the Host header
    m1=regex.match(i)
  
    #Extract and store the Host header
    if m1:
      t2=i.split(': ')
  
  return t2

def extract_directory(self,callbacks,url):
  t0=url.split('/')
  if len(t0) > 1:
    t0.pop(-1)
  i=0
  t1=''
  while i<len(t0):
    t1=t1+'/'+t0[i]
    i+=1

  return t1[1:]

def extract_urls(self,callbacks,url):
  t0=url.split('/')
  i=0
  t1=''
  while i<len(t0):
    t1=t1+'/'+t0[i]
    i+=1

  return t1[1:]

def get_referer_header_from_request(self,requestInfo):
  t1 = requestInfo.getHeaders()
  header_name='Referer:'

  regex=re.compile('^.*%s.*'%header_name,re.IGNORECASE)
  for i in t1:
    #Search for the Referer header
    m1=regex.match(i)

    #Extract and store the Referer header
    if m1:
      t2=i.split(': ')
      return t2

def get_setcookie_from_header(self,responseInfo):
  t1 = responseInfo.getHeaders()
  header_name='Set-Cookie:'

  #Search for the Set Cookie header
  regex=re.compile('^.*%s.*'%header_name,re.IGNORECASE)

  for i in t1:
    m1=regex.match(i)
    #Extract and store the Set Cookie header
    if m1:
      t2=i.split(': ')
      return t2

def get_response_code_from_headers(self,responseInfo):
  t1 = responseInfo.getHeaders()
  return t1

def get_location_from_headers(self,responseInfo):
  t1 = responseInfo.getHeaders()
  header_name='Location:'

  #Search for the Location header
  regex=re.compile('^.*%s.*'%header_name,re.IGNORECASE)
  for i in t1:
    m1=regex.match(i)
    #Extract and store the Location header
    if m1:
      t2=i.split(': ')
      return t2

def get_response_body(self,response_byte_array,responseInfo):
  responseBody=response_byte_array[responseInfo.getBodyOffset():]
  return responseBody

def get_banner_from_response(self,responseInfo):
  t1 = responseInfo.getHeaders()
  #header_name='Server:'
  header_name=['Server:','X-AspNet-Version:','X-AspNetMvc-Version:','X-Powered-By:','X-Requested-With:','X-UA-Compatible:','Via:']
 
  for h1 in header_name:
    regex=re.compile('^.*%s.*'%h1,re.IGNORECASE)
    for i in t1:
      #Search for the Server header
      m1=regex.match(i)

      #Extract and store the Server header
      if m1:
        return i
