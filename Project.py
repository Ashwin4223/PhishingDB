import PySimpleGUI as sg
import re    
import tldextract
import ssl
import socket
from bs4 import BeautifulSoup
import urllib.request
import whois
import datetime


#model building and dataset filtering part
import csv 
import sklearn as sk
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

#SQLite3
import sqlite3 as sql


def url_having_ip(url):
#using regular function
    symbol = re.findall(r'^(http|https)://\d+\.\d+\.\d+\.\d+\.*',url)
    if(len(symbol)!=0):
      return 1 #phishing
    else:
        return -1 #legitimate

def url_length(url):
    length=len(url)
    if(length<54):
        return -1
    elif(54<=length<=75):
        return 0
    else:
        return 1


def url_short(url):
    short_list = str(['bit.ly','t.co','tinyURL'])
    res = any(i in url for i in short_list)
    if (res == True):
        return 1
    else:
        return -1
    

def having_at_symbol(url):
    symbol=re.findall(r'@',url)
    if(len(symbol)==0):
        return -1
    else:
        return 1
    
def doubleSlash(url):
    return 0

def prefix_suffix(url):
    extracted=tldextract.extract(url)
    subDomain=extracted.subdomain
    domain=extracted.domain
    suffix=extracted.suffix
    #print(subDomain,domain,suffix)
    if(domain.count('-')):
       return 1
    else:
        return -1

def sub_domain(url):
    extracted=tldextract.extract(url)
    subDomain=extracted.subdomain
    domain=extracted.domain
    suffix=extracted.suffix
    #print(subDomain,domain,suffix)
    if(subDomain.count('.')==0):
        return -1
    elif(subDomain.count('.')==1):
        return 0
    else:
        return 1
    
def SSLfinal_State(url):
    try:
#check wheather contains https       
        if(re.search('^https',url)):
            usehttps = 1
        else:
            usehttps = 0
#getting the certificate issuer to later compare with trusted issuer 
        #getting host name
        extracted=tldextract.extract(url)
        subDomain=extracted.subdomain
        domain=extracted.domain
        suffix=extracted.suffix
        #print(subDomain,domain,suffix)
        host_name = domain + "." + suffix
        context = ssl.create_default_context()
        sct = context.wrap_socket(socket.socket(), server_hostname = host_name)
        sct.connect((host_name, 443))
        certificate = sct.getpeercert()
        issuer = dict(x[0] for x in certificate['issuer'])
        certificate_Auth = str(issuer['commonName'])
        certificate_Auth = certificate_Auth.split()
        if(certificate_Auth[0] == "Network" or certificate_Auth == "Deutsche"):
            certificate_Auth = certificate_Auth[0] + " " + certificate_Auth[1]
        else:         certificate_Auth = certificate_Auth[0] 
        trusted_Auth = ['Comodo','Symantec','GoDaddy','GlobalSign','DigiCert','StartCom','Entrust','Verizon','Trustwave','Unizeto','Buypass','QuoVadis','Deutsche Telekom','Network Solutions','SwissSign','IdenTrust','Secom','TWCA','GeoTrust','Thawte','Doster','VeriSign']        
#getting age of certificate
        startingDate = str(certificate['notBefore'])
        endingDate = str(certificate['notAfter'])
        startingYear = int(startingDate.split()[3])
        endingYear = int(endingDate.split()[3])
        Age_of_certificate = endingYear-startingYear
        
#checking final conditions
        if((usehttps==1) and (certificate_Auth in trusted_Auth) and (Age_of_certificate>=1) ):
            return -1 #legitimate
        elif((usehttps==1) and (certificate_Auth not in trusted_Auth)):
            return 0 #suspicious
        else:    
            return 1 #phishing
    except Exception as e:
        
        return 1

def domain_registration(url):
    try:
        w = whois.whois(url)
        updated = w.updated_date
        exp = w.expiration_date
        length = (exp[0]-updated[0]).days
        if(length<=365):
            return 1
        else:
            return -1
    except:
        return 0


def port(url):
    return 0

def https_token(url):
    extracted=tldextract.extract(url)
    subDomain=extracted.subdomain
    domain=extracted.domain
    suffix=extracted.suffix
    print(subDomain,domain,suffix)
    host =subDomain +'.' + domain + '.' + suffix 
    if(host.count('https')): #attacker can trick by putting https in domain part
        return 1
    else:
        return -1

def request_url(url):
    try:
        subDomain, domain, suffix = tldextract(url)
        websiteDomain = domain
        
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        imgs = soup.findAll('img', src=True)
        total = len(imgs)
        
        linked_to_same = 0
        avg =0
        for image in imgs:
            subDomain, domain, suffix = tldextract(image['src'])
            imageDomain = domain
            if(websiteDomain==imageDomain or imageDomain==''):
                linked_to_same = linked_to_same + 1
        vids = soup.findAll('video', src=True)
        total = total + len(vids)
        
        for video in vids:
            subDomain, domain, suffix = tldextract(video['src'])
            vidDomain = domain
            if(websiteDomain==vidDomain or vidDomain==''):
                linked_to_same = linked_to_same + 1
        linked_outside = total-linked_to_same
        if(total!=0):
            avg = linked_outside/total
            
        if(avg<0.22):
            return -1
        elif(0.22<=avg<=0.61):
            return 0
        else:
            return 1
    except:
        return 0


def url_of_anchor(url):
    try:
        extracted=tldextract.extract(url)
        subDomain=extracted.subdomain
        domain=extracted.domain
        suffix=extracted.suffix
        #print(subDomain,domain,suffix)
        websiteDomain = domain
        
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        anchors = soup.findAll('a', href=True)
        total = len(anchors)
        linked_to_same = 0
        avg = 0
        for anchor in anchors:
            subDomain, domain, suffix = tldextract(anchor['href'])
            anchorDomain = domain
            if(websiteDomain==anchorDomain or anchorDomain==''):
                linked_to_same = linked_to_same + 1
        linked_outside = total-linked_to_same
        if(total!=0):
            avg = linked_outside/total
            
        if(avg<0.31):
            return -1
        elif(0.31<=avg<=0.67):
            return 0
        else:
            return 1
    except:
        return 0
    
def Links_in_tags(url):
    try:
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        
        no_of_meta =0
        no_of_link =0
        no_of_script =0
        anchors=0
        avg =0
        for meta in soup.find_all('meta'):
            no_of_meta = no_of_meta+1
        for link in soup.find_all('link'):
            no_of_link = no_of_link +1
        for script in soup.find_all('script'):
            no_of_script = no_of_script+1
        for anchor in soup.find_all('a'):
            anchors = anchors+1
        total = no_of_meta + no_of_link + no_of_script+anchors
        tags = no_of_meta + no_of_link + no_of_script
        if(total!=0):
            avg = tags/total

        if(avg<0.25):
            return -1
        elif(0.25<=avg<=0.81):
            return 0
        else:
            return 1        
    except:        
        return 0

def sfh(url):
    return 0

def abnormal_url(url):
    return 0

def redirect(url):
    return 0

def on_mouseover(url):
    return 0

def age_of_domain(url):
    try:
        w = whois.query(url)
        start_date = w.creation_date
        current_date = datetime.datetime.now()
        age =(current_date-start_date[0]).days
        if(age>=180):
            return -1
        else:
            return 1
    except Exception as e:
        print(e)
        return 0
        
def dns(url):
    return 0

def web_traffic(url):
    return 0

def page_rank(url):
    return 0

def google_index(url):
    return 0


def links_pointing(url):
    return 0

def statistical(url):
    return 0

df = pd.read_csv('output.csv')

#renaming columns
df1 = df.copy()
col_list = ['has_IP_Address',
'Lengthy_URL','Shortining_Service','At_Symbol','double_slash_redirecting',
'Prefix_Suffix','having_Sub_Domain','SSLfinal_State',
'Domain_registeration_length','Favicon','port','HTTPS_token','Request_URL','URL_of_Anchor',
'Links_in_tags','SFH','Submitting_to_email',
'Abnormal_URL','Redirect','has_on_mouseover','RightClick','popUpWindow',
'Iframe','age_of_domain','DNSRecord','web_traffic',
'Page_Rank','Google_Index','Links_pointing_to_page','Statistical_report','Result']

df1.columns = col_list

# Removing features which have correlation between +/- 0.03
df1.drop(['Favicon','Iframe','popUpWindow','RightClick','Submitting_to_email'],axis=1,inplace=True)


# ## Model Building
# Preparing data for models
y=df1['Result'].values
X = df1.drop(['Result'],axis=1)
X_train,X_test,y_train,y_test = train_test_split(X,y,test_size=0.3,random_state=None)
rfc = RandomForestClassifier()
rfc = rfc.fit(X_train.values,y_train)

#SQLite3 table
conn = sql.connect('mydb.db')
conn.execute('DROP TABLE IF EXISTS websites')
conn.execute('''CREATE TABLE websites(website VARCHAR(100))''')
final_list = []
unblock_list = []
def repeat():
    cursor = conn.execute('SELECT * FROM websites')
    for row in cursor:
        final_list.append(row[0])

#Blocking Function
#Path for host file
#host_path = '/etc/hosts' #for Linux and MacOS
host_path = 'C://Windows//System32//drivers//etc//hosts'
ip_addr = '127.0.0.1'


def Block(website):
    b_w = []
    b_w.append(website)
    with open(host_path,'r+') as hf:
        file = hf.read()
        if website in file:
            pass
        else:
            hf.write(ip_addr +" "+ website + '\n')
    hf.close()
    #print(b_w)

def UnBlock(website):
    unblock = []
    unblock.append(website)
    with open(host_path,'r+') as hf:
        file = hf.readlines()
        hf.seek(0)
        for line in file:
            if not any(website in line for website in unblock):
                hf.write(line)       
                hf.truncate()
    hf.close()
    #print(file)

#GUI

    
DARK_HEADER_COLOR = '#1B2838'
T_PAD = (0,25)
col_1 = sg.Column([[sg.Text('Phishing Website Detector and Blocker',font = 'Any 20',background_color=DARK_HEADER_COLOR,size=(1000,1))]])
        
col_3 = sg.Column([
    [sg.Frame('Input:',
                  [[sg.Column([[sg.Text('URL:',font='Calibri 16')],
                   [sg.Input(key='-URL-IN-',size=(70,2.5))],
                   [sg.Button('Submit',size=(10,1),key='-URL-SUBMIT-')],
                   [sg.Text('',font = 'Calibri 16',expand_x=True,justification='center',pad=T_PAD,key='-RESULT-',visible=False)],
                   [sg.Push(),sg.Button('Blacklist',size=(10,1),key='-BLOCK-',visible=False),sg.Push()],
                   [sg.Push(),sg.Button('OK',size=(10,1),key='-OK-',visible=False),sg.Push()],
                   [sg.Push(),sg.Button('Report',size=(10,1),key='-REPORT-',visible=False),sg.Push()],
                   ])]],size=(450,400))]
    ])
repeat()
col_2 = sg.Column([
    [sg.Frame('Websites',
              [
                  [sg.Listbox(values=final_list,key='-B_L-',size=(100,12),select_mode='single')],
                  [sg.Button('Remove',size=(10,1),key='-UNBLOCK-')]
              ],size=(450,300))]])
              
               
layout = [[col_1],
          [col_3,col_2]]


window = sg.Window('Phishing Site Blocker',layout,size=(1000,500))
while True:
    event,values = window.read()
    if event == sg.WIN_CLOSED or event == 'exit':
        break

    if event == '-URL-SUBMIT-':
        url = values['-URL-IN-']
        res = [[url_having_ip(url), url_length(url), url_short(url), having_at_symbol(url), doubleSlash(url),
                prefix_suffix(url), sub_domain(url), SSLfinal_State(url), domain_registration(url), port(url),
                https_token(url), request_url(url), url_of_anchor(url), Links_in_tags(url), sfh(url), abnormal_url(url),
                redirect(url), on_mouseover(url), age_of_domain(url), dns(url), web_traffic(url), page_rank(url),
                google_index(url), links_pointing(url), statistical(url)]]

        pred = rfc.predict(res)
        if pred == 1:  # Phishing website
            window['-RESULT-'].update('This website is a phishing website', visible=True)
            window['-BLOCK-'].update(visible=True)
            window['-REPORT-'].update(visible=True)

            # Prepare feature results for explanation
            feature_results = {
                "URL contains IP address": url_having_ip(url),
                "URL length is suspicious": url_length(url),
                "URL uses shortening service": url_short(url),
                "URL contains '@' symbol": having_at_symbol(url),
                "URL has prefix/suffix issue": prefix_suffix(url),
                "URL has subdomain issue": sub_domain(url),
                "SSL certificate is invalid": SSLfinal_State(url),
                "Domain registration length is short": domain_registration(url),
                "URL contains 'https' token in domain": https_token(url),
                "Request URL is suspicious": request_url(url),
                "Anchor tags are suspicious": url_of_anchor(url),
                "Links in tags are suspicious": Links_in_tags(url),
                "Age of domain is too short": age_of_domain(url),
            }

            # Extract reasons for phishing
            reasons = [f"{feature}: {'Yes' if result == 1 else 'No'}" for feature, result in feature_results.items() if result == 1]

            # Extract domain details
            extracted = tldextract.extract(url)
            domain_info = {
                "Subdomain": extracted.subdomain,
                "Domain": extracted.domain,
                "Suffix": extracted.suffix
            }

        elif pred == -1:  # Legitimate website
            window['-RESULT-'].update('This website is not a phishing website', visible=True)
            window['-OK-'].update(visible=True)
            window['-REPORT-'].update(visible=True)

            # Extract domain details
            extracted = tldextract.extract(url)
            domain_info = {
                "Subdomain": extracted.subdomain,
                "Domain": extracted.domain,
                "Suffix": extracted.suffix
            }


    if event == '-REPORT-':
        if pred == 1:  # Phishing website
            sg.popup(
                "Reasons why this website is phishing:",
                "\n".join(reasons),
                "\n\nDomain Details:",
                "\n".join([f"{key}: {value}" for key, value in domain_info.items()]),
                title="LInk Report"
            )
        elif pred == -1:  # Legitimate website
            sg.popup(
                "Domain Details:",
                "\n".join([f"{key}: {value}" for key, value in domain_info.items()]),
                title="Domain Information"
            )

    if event == '-BLOCK-':
        Block(url)
        window['-URL-IN-'].update('')
        window['-RESULT-'].update(visible=False)
        window['-OK-'].update(visible=False)
        window['-REPORT-'].update(visible=False)
        final_list.append(url)
        for i in final_list:
            conn.execute("INSERT INTO websites(website) VALUES(?)", (i,))
        window['-B_L-'].update(values=final_list)

    if event == '-OK-':
        window['-URL-IN-'].update('')
        window['-RESULT-'].update(visible=False)
        window['-OK-'].update(visible=False)
        window['-BLOCK-'].update(visible=False)
        window['-REPORT-'].update(visible=False)

    if event == '-UNBLOCK-':
        url = values['-B_L-'][0]
        unblock_list.append(url)
        UnBlock(url)
        final_list.remove(url)
        for i in unblock_list:
            conn.execute('DELETE FROM websites WHERE website = ?', (i,))
        window['-B_L-'].update(values=final_list)

window.close()
