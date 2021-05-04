#! /usr/bin/env python
import os
import re
import sys
import time
import math
import copy
import datetime
from multiprocessing import Process
try:
    import requests, json
except ImportError:
    os.system('pip3 install requests')
try:
    from urllib.parse import urljoin
except ImportError:
     from urlparse import urljoin
try:
    import dns.resolver
except ImportError:
    print ('dnspython isn\'t installed, installing now.')
    os.system('pip3 install dnspython')
    print ('dnspython has been installed.....')
try:
    import emailprotectionslib.spf as spflib
    import emailprotectionslib.dmarc as dmarclib
except ImportError:
    print ('emailprotectionslib isn\'t installed, installing now.')
    os.system('pip3 install mailprotectionslib')
    print ('emailprotectionslib has been installed.....')
try:
    import dnslib
except ImportError:
    print ('dnslib isn\'t installed, installing now.')
    os.system('pip3 install dnslib')
    print ('dnslib has been installed.....')
try:
    import ssl
except ImportError:
    print ('ssl isn\'t installed, installing now.')
    os.system('pip install ssl')
    print ('ssl has been installed.....')
try:
    import nmap
except ImportError:
    print ('nmap isn\'t installed, installing now.')
    os.system('pip install python-nmap')
    print ('python-nmap has been installed.....')
try:
    import socket
except ImportError:
    print ('socket isn\'t installed, installing now.')
    os.system('pip install socket')
    print ('socket has been installed.....')
try:
    import requests
except ImportError:
    print ('requests isn\'t installed, installing now.')
    os.system('pip3 install requests')
    print ('requests has been installed.....')
try:
    import ipwhois
except ImportError:
    print ('ipwhois isn\'t installed, installing now.')
    os.system('pip3 install ipwhois')
    print ('ipwhois has been installed.....')
try:
   
    from urllib.request import urlopen, Request ,build_opener
    from urllib.parse import quote
    from urllib.error import URLError, HTTPError
except ImportError:
    print ('urllib isn\'t installed, installing now.')
    os.system('pip3 install urllib')
    print ('urllib has been installed.....')
try:
    import signal
except ImportError:
    print ('signal isn\'t installed, installing now.')
    os.system('pip3 install signal')
    print ('signal has been installed.....')
try:
    import urllib.parse as urlparse
except ImportError:
    print ('urlparse isn\'t installed, installing now.')
    os.system('pip3 install urlparse')
    print ('urlparse has been installed.....')
try:
    import lxml
except ImportError:
    print ('lxml isn\'t installed, installing now.')
    os.system('pip3 install lxml')
    print ('lxml has been installed.....')
try:
    from traceback import format_exc
except ImportError:
    print ('required from traceback import format_exc ')
try:
    from bs4 import BeautifulSoup
except ImportError:
    print ('BeautifulSoup isn\'t installed, installing now.')
    os.system('pip3 install BeautifulSoup')
    print ('BeautifulSoup has been installed.....')
try:
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print ('error on requests.packages.urllib3.disable_warnings()')

#----------------------------------lib imported end-----------------------------------    

#----------------------------------Pre-define TXT Output------------------------------

try: 
	file_object = open('HOCLOGFILE.txt', 'a') 
except: 
	file_object = open("HOCLOGFILE.txt", "w")



class Log:
	@classmethod
	def info(self,text):
		print(N + " #> " + G +  text)
		file_object.write('#>'+text+'\n')
	@classmethod
	def info1(self,text):
		print(G + " [>] " + N + text)
		file_object.write('[>]'+text+'\n')		
	@classmethod
	def info2(self,text):
		print(Y + " [!] " + Y + text)
		file_object.write('[!]'+text+'\n')
	@classmethod
	def info3(self,text):
		print(R + " [!] " + R + text)	
		file_object.write('[!]'+text+'\n')
intro = '''
        --------------------------------------------------
            		#    #   ####    #####      
            		#    #  #    #  #
            		######  #    #  #
            		#    #  #    #  #
            		#    #  #    #  #
            		#    #   ####    #####
            
            Version : 1.3
            Team Hackersonlineclub
            Website : https://hackersonlineclub.com
        --------------------------------------------------
    '''

#-----------------------------------color code & pre-define strings------------------------------------------
N = '\033[0m'
W = '\033[1;37m' 
B = '\033[1;34m' 
M = '\033[1;35m' 
R = '\033[1;31m' 
G = '\033[1;32m' 
Y = '\033[1;33m' 
C = '\033[1;36m'
underline = "\033[4m" 
log=False
finderurl = 'https://www.pagesinventory.com/search/?s='
errormsgreq = 'Error on getting request '
match = '/domain/(.*?).html(.*?)'
WHAT = 'WHAT YOU WANT TO DO?'
keybordexcpt = 'Keyboard Interruption! Exiting... '
exit = 'Press CTRL + C for EXIT'
retrypls ='Wrong target not able to get IP address Please retry '
sslnotfound = 'SSL is not Present on Target URL...Skipping... '
msgsinfo = 'This website have references to the following websites: '
presskey='Press a key to continue '
ABC = 'User-Agent'
BCD = 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0'
linkregex = re.compile('[^>](?:href\=|src\=|content\=\"http)[\'*|\"*](.*?)[\'|\"].*?>',re.IGNORECASE)
linkredirect = re.compile('(?:open\\(\"|url=|URL=|location=\'|src=\"|href=\")(.*?)[\'|\"]')
linksrobots = re.compile('(?:Allow\:|Disallow\:|sitemap\:).*',re.IGNORECASE)
information_disclosure = re.compile('(?:<address>)(.*)[<]',re.IGNORECASE)
user_agent = {'User-Agent': 'MMozilla/5.0 (Windows; U; Windows NT 5.1; it; rv:1.8.1.11)Gecko/20071127 Firefox/2.0.0.11'} 
visited=[]
def IPchk():
	os. system('clear')
	print(R + intro + '\n' + '\n' + W)
	file_object.write(intro+'\n')
	target = input('Enter target Website : >')#enter website domain name
	if 'http' in target:
		hostname = target.split('//')
		hostname = hostname[1]
	elif 'http' not in target:
		hostname = target
		target = 'http://{}'.format(target)
	elif ':' in hostname:
		hostname = hostname.split(':')
		hostname = hostname[0]
	else:
		Log.info3(' Error : Invalid URL / IP Entered'+ W)
		sys.exit(1)
	try:
		ip = socket.gethostbyname(hostname)
		RECO(hostname,target,ip)
	except Exception as e:
        	Log.info3(retrypls)
        	sys.exit(1)
#-----------------------------------RECO MENU function------------------------------------------
def RECO(hostname,target,ip):
	print('\n')
	Log.info2(' Hostname :'+ hostname)
	Log.info2(' Target protocal :'+ target)
	Log.info2(' Target IP address :'+ ip)
	print('\n')
	Log.info(WHAT)
	Log.info(' 1.  Header Information')
	Log.info(' 2.  SSL Certificate Information')
	Log.info(' 3.  Whois Lookup')
	Log.info(' 4.  Sub-domain Website')
	Log.info(' 5.  Robots.txt')
	Log.info(' 6.  Honeypot Detector using Shodan')
	Log.info(' 7.  Port Scanner using SYN ACK Scan')
	Log.info(' 8.  OS Finger Printing')
	Log.info(' 9.  Crawl Target Website (includes Email, Sub-Domain, File Type )')
	Log.info(' 10. DNS Look up')
	Log.info(' 11. Dmarc check for spoofing')
	Log.info(' 12. Test All Available Options')
	Log.info(' 0.  Change Target')
	Log.info(exit)	
	print('\n')
	RECO_var = input('Enter your choice: >')
	Log.info3(' TARGET :' + target)
	if(RECO_var=="1"):
		file_object = open('HOCLOGFILE.txt', 'a')
		RECO1(target) #Header
		a = input('Press enter for continue')
		RECO(hostname,target,ip)
		file_object.close()
	if(RECO_var=="2"):
		file_object = open('HOCLOGFILE.txt', 'a')
		RECO2(hostname) #SSL certificate
		a = input('Press enter for continue')
		RECO(hostname,target,ip)
		file_object.close()
	if(RECO_var=="3"):
		file_object = open('HOCLOGFILE.txt', 'a')
		RECO3(ip) #Whois lookup
		a = input('Press enter for continue')
		RECO(hostname,target,ip) 
		file_object.close()       
	if(RECO_var=="4"):
		file_object = open('HOCLOGFILE.txt', 'a')
		RECO5(hostname) #sub domain
		a = input('Press enter for continue')
		RECO(hostname,target,ip) 
		file_object.close()    
	if(RECO_var=="5"):
		file_object = open('HOCLOGFILE.txt', 'a')
		RECORobot(target) #Robots.txt
		a = input('Press enter for continue')
		RECO(hostname,target,ip)
		file_object.close()
	if(RECO_var=="6"):
		file_object = open('HOCLOGFILE.txt', 'a')
		RECOHoneypot(ip) #Honeypot Detector
		a = input('Press enter for continue')
		RECO(hostname,target,ip)
		file_object.close()
	if(RECO_var=="9"):
		file_object = open('HOCLOGFILE.txt', 'a')
		RECO4(target) #crawl target
		a = input('Press enter for continue')
		RECO(hostname,target,ip)
		file_object.close()
	if(RECO_var=="8"):
		file_object = open('HOCLOGFILE.txt', 'a')
		RECOOSprinting(ip) #OS Fingerprinting
		a = input('Press enter for continue')
		RECO(hostname,target,ip)
		file_object.close()
	if(RECO_var=="7"):
		file_object = open('HOCLOGFILE.txt', 'a')
		RECOPortScanner(ip) #Port Scanner
		a = input('Press enter for continue')
		RECO(hostname,target,ip)
		file_object.close()
	if(RECO_var=="10"):
		file_object = open('HOCLOGFILE.txt', 'a')
		a = input('Press enter for continue')
		RECO10(hostname)    #DNS finder
		RECO(hostname,target,ip)
		file_object.close()
	if(RECO_var=="11"):
		file_object = open('HOCLOGFILE.txt', 'a')
		a = input('Press enter for continue')
		RECO11(hostname)   # DMARC finder
		RECO(hostname,target,ip)
		file_object.close()
	if(RECO_var=="12"):
		file_object = open('HOCLOGFILE.txt', 'a')
	 # Test all the avaible option
		RECO1(target) #Header
		RECO2(hostname) #SSL certificate
		RECO3(ip) #Whois lookup
		RECO5(hostname) #Sub domain
		RECORobot(target) #Robots.txt
		RECOHoneypot(ip) #Honeypot Detector
		RECOOSprinting(ip) #OS Fingerprinting
		RECOPortScanner(ip) #Port Scanner
		RECO10(hostname) #DNS FINDER target
		RECO11(hostname) #DMARC target
		RECO4(target) #Crawl target
		RECO(hostname,target,ip) #Change target
		file_object.close()
	if(RECO_var=="0"):
        	IPchk() #Change target
	if(RECO_var !="1" and RECO_var !="2" and RECO_var !="3" and RECO_var !="4" and RECO_var !="5" and RECO_var !="6" and RECO_var !="8" and RECO_var !="9" and RECO_var !="10" and RECO_var !="7" and RECO_var !="0" and RECO_var !="11" and RECO_var !="12"):
		print(R + 'Wrong Key Enter Retry...' + presskey)
		input()
		RECO(hostname,target,ip)
		
#----------------------------------- RECO Header------------------------------------
def RECO1(target):
	print(R + '---------------------------------------------------')
	file_object.write('---------------------------------------------------\n')
	Log.info('Headers :')
	file_object.write('---------------------------------------------------\n')
	print(R + '---------------------------------------------------')
	ReQ = requests.get(target, verify=False, timeout=10)
	for k, v in ReQ.headers.items():
		Log.info1('{} : '.format(k) + v)
#-----------------------------------RECO SSL ---------------------------------------
def RECO2(hostname):
	print(R + '---------------------------------------------------')
	file_object.write('---------------------------------------------------\n')
	Log.info('SSL Certificate Information : ')
	file_object.write('---------------------------------------------------\n')
	print(R + '---------------------------------------------------')
	ctx = ssl.create_default_context()
	s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
	try:
		try:
			s.connect((hostname, 443))
			info = s.getpeercert()
			subject = dict(x[0] for x in info['subject'])
			issuer = dict(y[0] for y in info['issuer'])
		except:
			ctx = ssl._create_unverified_context()
			s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
			s.connect((hostname, 443))
			info = s.getpeercert(True)
			info = ssl.get_server_certificate((hostname, 443))
			f = open('{}.pem'.format(hostname), 'w')
			f.write(info)
			f.close()
			cert_dict = ssl._ssl._test_decode_cert('{}.pem'.format(hostname))
			subject = dict(x[0] for x in cert_dict['subject'])
			issuer = dict(y[0] for y in cert_dict['issuer'])
			info = cert_dict
			os.remove('{}.pem'.format(hostname))
		try:
			for k, v in subject.items():
				Log.info1('{} : '.format(str(k)) + W + str(v))
			for k, v in issuer.items():
				Log.info1('{} : '.format(str(k)) + W + str(v))
			Log.info1('Version : ' + W + str(info['version']))
			Log.info1('Serial Number : ' + W + str(info['serialNumber']))
			Log.info1('Not Before : ' + W + str(info['notBefore']))
			Log.info1('Not After : ' + W + str(info['notAfter']))
			Log.info1('OCSP : ' + W + str(info['OCSP']))
			Log.info1('subject Alt Name : ' + W + str(info['subjectAltName']))
			Log.info1('CA Issuers : ' + W + str(info['caIssuers']))
			Log.info1('CRL Distribution Points : ' + W + str(info['crlDistributionPoints']))
		except KeyError:
			pass

	except:
		Log.info3(sslnotfound)
#-----------------------------------RECO Whois -------------------------------------
def RECO3(ip):
	print(R + '---------------------------------------------------')
	file_object.write('---------------------------------------------------\n')
	Log.info('Whois Lookup : ')
	file_object.write('---------------------------------------------------\n')
	print(R + '---------------------------------------------------')
	try:
		Lookup = ipwhois.IPWhois(ip)
		results = Lookup.lookup_whois()
		Log.info1('NIR : ' + W + str(results['nir']))
		Log.info1('ASN Registry : ' + W + str(results['asn_registry']))
		Log.info1('ASN : ' + W + str(results['asn']))
		Log.info1('ASN CIDR : ' + W + str(results['asn_cidr']))
		Log.info1('ASN Country Code : ' + W + str(str(results['asn_country_code'])))
		Log.info1('ASN Date : ' + W + str(results['asn_date']))
		Log.info1('ASN Description : ' + W + str(results['asn_description']))
		for k, v in results['nets'][0].items():
			Log.info1('{} : '.format(str(k)) + W + str(v))
	except Exception as e:
		Log.info3(' Error : ' + C + str(e) + W)
		pass
    	#keyboardinterrrupt handler
	except KeyboardInterrupt:
    	    Log.info3(keybordexcpt)
    	    sys.exit(1)
	except Exception as inst:
            Log.info1( 'Exception in RECO3() function')
            sys.exit(1)
            

#----------------------------------Scan url -------------------------------------
def scan_URL(url,TOR):
	Log.info1(url)
#-------------------------------Link in web page finder-----------------------------

def links_to_page(base,TOR,cookie):
	session = get_session(TOR,cookie) #Getting session 
	lt=[]	#list 
	text=session.get(base).text #Getting page content  
	visit=BeautifulSoup(text,"html.parser")	#beautifulsoup  extract html parse 
	for objects in visit.find_all("a",href=True):
		url=objects["href"]
		if url.startswith("http://") or url.startswith("https://"):
			continue
		elif url.startswith("mailto:") or url.startswith("javascript:"):
			continue
		elif urljoin(base,url) in visited:
			continue
		else:
			lt.append(urljoin(base,url))
			visited.append(urljoin(base,url))
	return lt #returl urls 

#--------------------------------- Crawl Website ----------------------------------
def crawl(url,depth,TOR,cookie):
	urls=links_to_page(url,TOR,cookie) #Extract link from the page
	for url in urls:
		p=Process(target=scan_URL, args=(url,TOR)) 	#scan_xss(url,payload,TOR,cookie)
		p.start()
		p.join()
		if depth != 0:
			crawl(url,depth-1,TOR,cookie) # Website crawling  
		else:
			break	

#--------------------------------- TOR SESSION --------------------------------------
def get_session(TOR,cookie):
	session = requests.session()# Request Session
	if(TOR == True): #if want to use tor set proxies
		session.proxies = {}
		session.proxies['http']='socks5h://127.0.0.1:9050'
		session.proxies['https']='socks5h://127.0.0.1:9050'
	else:
		proxies = None # without tor 
		session.proxies = proxies
	session.headers=user_agent
	if(cookie==False):
		return session #return session without cookie
	else:
		try:
			session.cookies.update(json.loads(cookie))#return session with cookie 
		except:
			return session  #return session without cookie
		return session




#-----------------------------------RECO web crawl ---------------------------------
def RECO4(weburl):
	print(R + '---------------------------------------------------')
	file_object.write('---------------------------------------------------\n')
	Log.info('Web Crawler :')
	file_object.write('---------------------------------------------------\n')
	print(R + '---------------------------------------------------')
	coe=False
	TOR = False
	ses = get_session(TOR,coe)#call session (TOR=Trure/False, cookie=False)
	
	try:
		if ("https://" not in weburl and "http://" not in weburl):
			weburl = "http://{}".format(weburl)
	except Exception as e:
		print(str(e))
		sys.exit(1)
	depth = 50
	TOR =False
	cookies = False
	crawl(weburl,depth,TOR,cookies)#call crawler
#-----------------------------------RECO subdomain ---------------------------------
def RECO5(target):
    print(R + '---------------------------------------------------')
    file_object.write('---------------------------------------------------\n')
    Log.info('SubDomain Finder :')
    file_object.write('---------------------------------------------------\n')
    print(R + '---------------------------------------------------')
    try:
    	uRl = finderurl + target
    	requ = requests.get(uRl)
    except:
    	Log.info3(errormsgreq)
    try:
    	response = requ.content.decode('utf-8')
    except:
    	Log.info3(errormsgreq)
    if 'Search result for' in response:
	    if re.search(match, response):
	        for i in re.findall(match, response):
	            Log.info1(i[0])
    elif 'Nothing was found' in response:
	    Log.info2('No Subdomains Found For This : '+ target)
    else:
	    Log.info3('No Subdomains Found For This : '+ target)


#-----------------------------------DNS RECORD-------------------------------------
def A_RECORD(domain):# Finding A record
	result = dns.resolver.resolve(domain, 'A')
	# Printing record
	for val in result:
	    a_record = 'A Record : '+ val.to_text()
	    Log.info(a_record)

def AAA_RECORD(domain):# Finding AAAA record
	# Finding AAAA record
	result = dns.resolver.resolve(domain, 'AAAA')
	# Printing record
	for val in result:
	    a_record = 'AAAA Record : '+ val.to_text()
	    Log.info(a_record)
	
def PTR_RECORD(domain):# Finding PTR record
# Finding AAAA record
	result = dns.resolver.resolve(domain, 'PTR')
	# Printing record
	for val in result:
	    a_record = 'PTR Record : '+ val.to_text()
	    Log.info(a_record)

def NS_RECORD(domain):# Finding NS record
# Finding AAAA record
	result = dns.resolver.resolve(domain, 'NS')
	# Printing record
	for val in result:
	    a_record = 'NS Record : '+ val.to_text()
	    Log.info(a_record)

def MX_RECORD(domain):# Finding MX record
# Finding AAAA record
	result = dns.resolver.resolve(domain, 'MX')
	# Printing record
	for val in result:
	    a_record = 'MX Record : '+ val.to_text()
	    Log.info(a_record)

def SOA_RECORD(domain):# Finding SOA record
# Finding AAAA record
	result = dns.resolver.resolve(domain, 'SOA')
	# Printing record
	for val in result:
	    a_record = 'SOA Record : '+ val.to_text()
	    Log.info(a_record)

def CNAME_RECORD(domain):# Finding CNAME record
# Finding AAAA record
	result = dns.resolver.resolve(domain, 'CNAME')
	# Printing record
	for val in result:
	    a_record = 'CNAME Record : '+ val.to_text()
	    Log.info(a_record)
	    
def TXT_RECORD(domain):# Finding TXT record
# Finding AAAA record
	result = dns.resolver.resolve(domain, 'TXT')
	# Printing record
	for val in result:
	    a_record = 'TXT Record : '+ val.to_text()
	    Log.info(a_record)
def RECO10(domain):
        print(R + '---------------------------------------------------')
        file_object.write('---------------------------------------------------\n')
        Log.info('DNS Records :')
        file_object.write('---------------------------------------------------\n')
        print(R + '---------------------------------------------------')
        try:
            A_RECORD(domain)
        except:
            Log.info2("A Record not found  !")
        try:
            AAA_RECORD(domain)
        except:
            Log.info2("AAAA Record not found  !")
        try:
            PTR_RECORD(domain)
        except:
            Log.info2("PTR Record not found  !")
        try:
            NS_RECORD(domain)
        except:
            Log.info2("NS Record not found  !")
        try:
            MX_RECORD(domain)
        except:
            Log.info2("MX Record not found  !")
        try:
            SOA_RECORD(domain)
        except:
            Log.info2("SOA Record not found  !")
        try:
            CNAME_RECORD(domain)
        except:
            Log.info2("CNAME Record not found  !")
        try:
            TXT_RECORD(domain)
        except:
            Log.info2("TXT Record not found  !")
#-----------------------------------Dmarc ----------------------------------------
def check_spf_redirect_mechanisms(spf_record):
    redirect_domain = spf_record.get_redirect_domain()

    if redirect_domain is not None:
        Log.info("Processing SPF redirect domain: %s" % redirect_domain)

        return is_spf_record_strong(redirect_domain)

    else:
        return False


def check_spf_include_mechanisms(spf_record):
    include_domain_list = spf_record.get_include_domains()

    for include_domain in include_domain_list:
        Log.info("Processing SPF include domain: %s" % include_domain)

        strong_all_string = is_spf_record_strong(include_domain)

        if strong_all_string:
            return True

    return False


def is_spf_redirect_record_strong(spf_record):
    Log.info("Checking SPF redirect domian: %(domain)s" % {"domain": spf_record.get_redirect_domain})
    redirect_strong = spf_record._is_redirect_mechanism_strong()
    if redirect_strong:
        Log.info2("Redirect mechanism is strong.")
    else:
        Log.info2("Redirect mechanism is not strong.")

    return redirect_strong


def are_spf_include_mechanisms_strong(spf_record):
    Log.info("Checking SPF include mechanisms")
    include_strong = spf_record._are_include_mechanisms_strong()
    if include_strong:
        Log.info2("Include mechanisms include a strong record")
    else:
        Log.info2("Include mechanisms are not strong")

    return include_strong


def check_spf_include_redirect(spf_record):
    other_records_strong = False
    if spf_record.get_redirect_domain() is not None:
        other_records_strong = is_spf_redirect_record_strong(spf_record)

    if not other_records_strong:
        other_records_strong = are_spf_include_mechanisms_strong(spf_record)

    return other_records_strong


def check_spf_all_string(spf_record):
    strong_spf_all_string = True
    if spf_record.all_string is not None:
        if spf_record.all_string == "~all" or spf_record.all_string == "-all":
            Log.info2("SPF record contains an All item: " + spf_record.all_string)
        else:
            Log.info3("SPF record All item is too weak: " + spf_record.all_string)
            strong_spf_all_string = False
    else:
        Log.info3("SPF record has no All string")
        strong_spf_all_string = False

    if not strong_spf_all_string:
        strong_spf_all_string = check_spf_include_redirect(spf_record)

    return strong_spf_all_string


def is_spf_record_strong(domain):
    strong_spf_record = True
    spf_record = spflib.SpfRecord.from_domain(domain)
    if spf_record is not None and spf_record.record is not None:
        Log.info("Found SPF record:")
        Log.info(str(spf_record.record))

        strong_all_string = check_spf_all_string(spf_record)
        if strong_all_string is False:

            redirect_strength = check_spf_redirect_mechanisms(spf_record)
            include_strength = check_spf_include_mechanisms(spf_record)

            strong_spf_record = False

            if redirect_strength is True:
                strong_spf_record = True

            if include_strength is True:
                strong_spf_record = True
    else:
        Log.info3(domain + " has no SPF record!")
        strong_spf_record = False

    return strong_spf_record


def get_dmarc_record(domain):
    dmarc = dmarclib.DmarcRecord.from_domain(domain)
    if dmarc is not None and dmarc.record is not None:
        Log.info("Found DMARC record:")
        Log.info(str(dmarc.record))
    return dmarc


def get_dmarc_org_record(base_record):
    org_record = base_record.get_org_record()
    if org_record is not None:
        Log.info("Found DMARC record:")
        Log.info(str(org_record.record))
    return org_record


def check_dmarc_extras(dmarc_record):
    if dmarc_record.pct is not None and dmarc_record.pct != str(100):
            Log.info2("DMARC pct is set to " + dmarc_record.pct + "% - might be possible")

    if dmarc_record.rua is not None:
        Log.info2("Aggregate reports will be sent: " + dmarc_record.rua)

    if dmarc_record.ruf is not None:
        Log.info2("Forensics reports will be sent: " + dmarc_record.ruf)


def check_dmarc_policy(dmarc_record):
    policy_strength = False
    if dmarc_record.policy is not None:
        if dmarc_record.policy == "reject" or dmarc_record.policy == "quarantine":
            policy_strength = True
            Log.info2("DMARC policy set to " + dmarc_record.policy)
        else:
            Log.info3("DMARC policy set to " + dmarc_record.policy)
    else:
        Log.info3("DMARC record has no Policy")

    return policy_strength


def check_dmarc_org_policy(base_record):
    policy_strong = False

    try:
        org_record = base_record.get_org_record()
        if org_record is not None and org_record.record is not None:
            Log.info("Found DMARC record:")
            Log.info(str(org_record.record))

            if org_record.subdomain_policy is not None:
                if org_record.subdomain_policy == "none":
                    Log.info3("Organizational subdomain policy set to %(sp)s" % {"sp": org_record.subdomain_policy})
                elif org_record.subdomain_policy == "quarantine" or org_record.subdomain_policy == "reject":
                    Log.info2("Organizational subdomain policy explicitly set to %(sp)s" % {"sp": org_record.subdomain_policy})
                    policy_strong = True
            else:
                Log.info("No explicit organizational subdomain policy. Defaulting to organizational policy")
                policy_strong = check_dmarc_policy(org_record)
        else:
            Log.info3("No organizational DMARC record")

    except dmarclib.OrgDomainException:
        Log.info3("No organizational DMARC record")

    return policy_strong


def is_dmarc_record_strong(domain):
    dmarc_record_strong = False

    dmarc = get_dmarc_record(domain)

    if dmarc is not None and dmarc.record is not None:
        dmarc_record_strong = check_dmarc_policy(dmarc)

        check_dmarc_extras(dmarc)
    elif dmarc.get_org_domain() is not None:
        Log.info("No DMARC record found Looking for organizational record")
        dmarc_record_strong = check_dmarc_org_policy(dmarc)
    else:
        Log.info3(domain + " has no DMARC record!")

    return dmarc_record_strong
def RECO11(domain):
        print(R + '---------------------------------------------------')
        file_object.write('---------------------------------------------------\n')
        Log.info('Dmarc Details :')
        file_object.write('---------------------------------------------------\n')
        print(R + '---------------------------------------------------')
        spoofable = False
        is_spf_record_strong(domain)
        dmarc_rec= is_dmarc_record_strong(domain)
        if dmarc_rec is False:
            spoofable = True
        else:
            spoofable = False
        if spoofable:
            Log.info3("Spoofing possible for " + domain)
        else:
            Log.info2("Spoofing not possible for " + domain)
#-----------------------------------RECO RobotTxt ---------------------------------
def RECORobot(target):
	print(R + '---------------------------------------------------')
	file_object.write('---------------------------------------------------\n')
	Log.info('Robots.txt Finder :')
	file_object.write('---------------------------------------------------\n')
	print(R + '---------------------------------------------------')
	try:
	 	req = requests.get(target)
	 	UTC = req.url
	except:
        	Log.info2('Error on getting responce')
        	sys.exit(1)
	url_ = UTC + "/robots.txt" 
	try:
		requ = requests.get(url_)
		request = requ.content.decode('utf-8')
	except:
		Log.info3(errormsgreq)
	try:
		if 'User-agent' in request:
			if len(request) != 5:
				list = request.strip("").split("\n")
				for inks in list:
					if len(inks) != 0:
						Log.info1(inks)
		else:
			Log.info3('No Robots.txt Found For This : '+ target)
	except:
            Log.info3(errormsgreq)

#-----------------------------------RECO Honeypot Detector----------------------------
def RECOHoneypot(ip):
	print(R + '---------------------------------------------------')
	file_object.write('---------------------------------------------------\n')
	Log.info('Honeypot Detector :')
	file_object.write('---------------------------------------------------\n')
	print(R + '---------------------------------------------------')
	URLINK = "https://api.shodan.io/labs/honeyscore/" + ip + "?key=C23OXE0bVMrul2YeqcL7zxb6jZ4pj2by"
	try:
		requ = requests.get(URLINK)
		request = requ.content.decode('utf-8')
	except:
	    	Log.info3(errormsgreq)	
	try:	
		probability = str(float(request) * 10)
		if float(request) < 0.5:
			Log.info1("Honeypot Percent : " + probability)
		else:
			Log.info3("Honeypot Percent : " + probability)
	except:
		Log.info3(errormsgreq)
#-----------------------------------OS Finger Printing-------------------------------
def RECOOSprinting(ip):
	print(R + '---------------------------------------------------')
	file_object.write('---------------------------------------------------\n')
	Log.info('OS Finger Printing :')
	file_object.write('---------------------------------------------------\n')
	print(R + '---------------------------------------------------')
	try:	
		nm_scanner=nmap.PortScanner()
		nm_scan=nm_scanner.scan(ip,'80',arguments='-O')	
	except Exception as e:
		Log.info3(errormsgreq + str(e)) 
	try:
		Log.info1("The host is : "+ nm_scan['scan'][ip]['status']['state'])
	except:
		Log.info3("errormsgreq")
	try:
		Log.info1("Port 80 is : "+ nm_scan['scan'][ip]['tcp'][80]['state'])
	except:
		Log.info3("errormsgreq")
	try:
		Log.info1("Scanning method is : "+nm_scan['scan'][ip]['tcp'][80]['reason'])
	except:
		Log.info3("errormsgreq")
	
	try:
		Log.info1("Predicted Operating System is : "+nm_scan['scan'][ip]['osmatch'][0]['osclass'][0]['osfamily'])
	except:
		Log.info3("Predicted Operating System is : No OS matches for host")
	
	try:
		Log.info1("OS Prediction percentage is : "+nm_scan['scan'][ip]['osmatch'][0]['accuracy'])
	except:
		Log.info3("OS Prediction percentage is : Null because No OS matches for host")


#-----------------------------------Port Scanner --------------------------------------
def RECOPortScanner(ip):
	nm_scanner = nmap.PortScanner()
	print(R + '---------------------------------------------------')
	file_object.write('---------------------------------------------------\n')
	Log.info('Port Scanner :')
	file_object.write('---------------------------------------------------\n')
	print(R + '---------------------------------------------------')
	try:
		nm_scanner.scan(ip)
		ports = nm_scanner[ip]['tcp'].keys()
		for port in ports:
			state = nm_scanner[ip]['tcp'][port]['state']
			service = nm_scanner[ip]['tcp'][port]['name']
			product = nm_scanner[ip]['tcp'][port]['product']
			name = nm_scanner[ip]['tcp'][port]['name']
			extrainfo = nm_scanner[ip]['tcp'][port]['extrainfo']
			reason = nm_scanner[ip]['tcp'][port]['reason']
			version = nm_scanner[ip]['tcp'][port]['version']
			conf = nm_scanner[ip]['tcp'][port]['conf']
			if state == 'open':
				Log.info1("Open port : "+str(port))
				Log.info1("State : "+str(state))
				Log.info1("Service : "+str(service))
				Log.info1("Product : "+str(product))
				Log.info1("Name : "+str(name))
				Log.info1("Extrainfo : "+str(extrainfo))
				Log.info1("Reason : "+str(reason))
				Log.info1("Version : "+str(version))
				Log.info1("Conf : "+str(conf)+"\n")		
	except:
		Log.info3(errormsgreq) 
#-----------------------------------main start --------------------------------------
if __name__ == '__main__':   
	try:
		IPchk()  #Calling main menu     
	except KeyboardInterrupt:
		print(keybordexcpt + '\n') #keyboard interruption
		sys.exit(1)
	except Exception as inst:
		print('Exception in __name__ == __main__ function')
		print(' [!] ',str(inst))#Error in code SS
		sys.exit(1)    

