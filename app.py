from flask import Flask, request, jsonify, render_template
import pickle
import re    
from tldextract import extract
import ssl
import socket
from bs4 import BeautifulSoup
import urllib.request
import whois
import datetime
from urllib.request import urlopen
from selenium import webdriver
from sklearn.externals import joblib
from selenium.webdriver.chrome.options import Options

app = Flask(__name__)
model = joblib.load(open('profit.pkl', 'rb'))


def pscan(port):
    try:
        con = s.connect((url,port))
        return True
    except:
        return False

def url_having_ip(url):
    try:
        regex = '''(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'''
        if(re.search(regex, url)):
            return 1
        else:  
            return -1
    except:
        return 0

def url_length(url):
    try:
        length=len(url)
        if(length<54):
            return -1
        elif(54<=length<=75):
            return 0
        else:
            return 1
    except:
        return 0

def url_short(url):
    try:
        if(re.search('tinyurl',url) or re.search(r'bit.ly',url) or re.search(r'goo.gl',url) or re.search(r'ow.ly',url)
           or re.search(r'buff.ly',url)):
            return 1
        else:
            return -1
    except:
        return 0

def having_at_symbol(url):
    try:
        symbol=re.findall(r'@',url)
        if(len(symbol)==0):
            return -1
        else:
            return 1 
    except:
        return 0

def doubleSlash(url):
    try:
        b = ''
        if(url[5] == '/' and url[6] == '/'):
            b = a[7:]
        elif(url[6] == '/' and url[7] == '/'):
            b = url[8:]
        out = re.search(r'//',b)
        if(re.search(r'//',b)):
            return 1
        else:
            return -1
    except:
        return 0

def prefix_suffix(url):
    try:
        subDomain, domain, suffix = extract(url)
        if(domain.count('-')):
            return 1
        else:
            return -1
    except:
        return 0

def sub_domain(url):
    try:
        subDomain, domain, suffix = extract(url)
        if(subDomain.count('.')==0):
            return -1
        elif(subDomain.count('.')==1):
            return 0
        else:
            return 1
    except:
        return 0

def SSLfinal_State(url):
    try:
        if(re.search('^https',url)):
            usehttps = 1
        else:
            usehttps = 0
        #getting the certificate issuer to later compare with trusted issuer 
        #getting host name
        subDomain, domain, suffix = extract(url)
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
        else:
            certificate_Auth = certificate_Auth[0] 
        print(certificate_Auth)
        trusted_Auth = ['Comodo','Symantec','GoDaddy','GlobalSign','DigiCert','StartCom','Entrust','Verizon',
                        'Trustwave','Unizeto','Buypass','QuoVadis','Deutsche Telekom','Network Solutions',
                        'SwissSign','IdenTrust','Secom','TWCA','GeoTrust','Thawte','Doster','VeriSign', 
                        'DigiCert', 'Let\'s', 'GTS', 'COMODO']        
        #getting age of certificate
        print(certificate)

        startingDate = str(certificate['notBefore'])
        print(startingDate)

        endingDate = str(certificate['notAfter'])
        print(endingDate)

        startingYear = int(startingDate.split()[3])
        #print(startingYear)

        endingYear = int(endingDate.split()[3])
        #print(endingYear)

        sY = int(startingYear)
        sD = int(startingDate.split()[1])

        eY = int(endingYear)
        eD = int(startingDate.split()[1])
        d = dict({"Jan":1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12})

        s = datetime.datetime(sY, d[startingDate.split()[0]], sD)
        print(s)
        dd = datetime.datetime(eY, d[endingDate.split()[0]], eD)
        print(dd)
        da = (dd - s).days
        print(da)

        Age_of_certificate = endingYear-startingYear
        print(Age_of_certificate)  
        #checking final conditions
        if((usehttps==1) and (certificate_Auth in trusted_Auth) and (da>=90) ):
            return -1 #legitimate
            #print(-1)
        elif((usehttps==1) and (certificate_Auth not in trusted_Auth)):
            return 0 #suspicious
            #print(0)
        else:
            return 1 #phishing
            #print(1)
    except Exception as e:
        return 1        

def domain_registration(url):
    try:
        w = whois.whois(url)
        updated = w.updated_date
        exp = w.expiration_date
        length = (exp-updated[0]).days
        if(length<=365):
            return 1
        else:
            return -1
    except Exception as e:
        return 0
        

def favicon(url):
    try:
        sD, d, s = extract(url)
        html = urlopen(url)
        content = html.read()    
        c = ''
        soup = BeautifulSoup(content, 'html5lib')
        for a in soup.findAll('link',href=True):
            if (re.findall(r'favicon', a['href']) or re.findall(r'.ico', a['href'])):
                c = a['href']
                break
        subDomain, domain, suffix = extract(c)
        linkDomain = domain
        if(linkDomain == '' or linkDomain == d):
            return -1
        else:
            return 1
    except:
        return 0

def port(url):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        '''21 22 23 445 1433 1521 3306 3389'''
        if(pscan(21) or pscan(22) or pscan(23) or pscan(445) or
           pscan(1433) or pscan(1521) or pscan(3306) or pscan(3389)):
            return 1
        else:
            return -1
    except:
        return 0

def https_token(url):
    try:
        subDomain, domain, suffix = extract(url)
        host =subDomain +'.' + domain + '.' + suffix 
        if(host.count('https')): #attacker can trick by putting https in domain part
            return 1
        else:
            return -1
    except:
        return 0

def request_url(url):
    try:
        subDomain, domain, suffix = extract(url)
        websiteDomain = domain
        
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        imgs = soup.findAll('img', src=True)
        total = len(imgs)
        
        linked_to_same = 0
        avg =0
        for image in imgs:
            subDomain, domain, suffix = extract(image['src'])
            imageDomain = domain
            if(websiteDomain==imageDomain or imageDomain==''):
                linked_to_same = linked_to_same + 1
        vids = soup.findAll('video', src=True)
        total = total + len(vids)
        
        for video in vids:
            subDomain, domain, suffix = extract(video['src'])
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
        subDomain, domain, suffix = extract(url)
        websiteDomain = domain
        
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        anchors = soup.findAll('a', href=True)
        total = len(anchors)
        linked_to_same = 0
        avg = 0
        for anchor in anchors:
            subDomain, domain, suffix = extract(anchor['href'])
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
    try:
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        sD, d, s = extract(url)
        tot = l = s = p = 0
        for a in soup.findAll('form', action = True):
            link = a['action']
            tot = tot + 1
            subDomain, domain, suffix = extract(a['action'])
            if(link == ''):
                p = p + 1
            elif(domain == d or domain == ''):
                l = l + 1
            else:
                s = s + 1
        
        if(l == tot):
            return -1
        else:
            if(p > 0):
                return 1
            if(s > 0):
                return 0
    except:
        return 0

def email_submit(url):
    try:
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        if(soup.find('mailto:')):
            return 1
        else:
            return -1 
    except:
        return 0

def abnormal_url(url):
    try:
        subDomain, domain, suffix = extract(url)
        host_name = domain + "." + suffix
        context = ssl.create_default_context()
        sct = context.wrap_socket(socket.socket(), server_hostname = host_name)
        sct.connect((host_name, 443))
        certificate = sct.getpeercert()
        issuer = dict(x[0] for x in certificate['subject'])
        name = str(issuer['organizationName'])
        if( domain in name.lower()):
            return -1
        else:
            return 1
    except:
        return 0

def redirect(url):
    try:
        sD, d, s = extract(url)
        html = urlopen(url)
        content = html.read()    
        soup = BeautifulSoup(content, 'html5lib')
        count = 0
        c = ""
        for i in soup.findAll('a',href=True):
            c = i['href']
            subDomain, domain, suffix = extract(c)
            if(domain != "" and domain != d):
                count = count + 1
        
        if(count <= 1):
            return -1
        elif(count >= 2 and count < 4):
            return 0
        else:
            return 1
    except:
        return 0

def on_mouseover(url):
    return 0

def rightClick(url):
    try:
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        s = str(soup)
        if(re.search("contextmenu", s) and re.search("preventDefault()", s)):
            return 1
        else:
            return -1
    except:
        return 0

def popup(url):
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--window-size=1920x1080")
        driver = webdriver.Chrome(executable_path='G:\\VIT\SEM8\\chromedriver_win32\\chromedriver.exe')
        driver.get(url)
        c = 0
        main_page = driver.current_window_handle 
        for handle in driver.window_handles:
            if (handle != main_page): 
                driver.switch_to.window(handle)
                html = driver.page_source
                if(re.search(r"<input", html)):
                    c = c + 1
        if(c > 0):
            driver.close()
            return 1
        else:
            driver.close()
            return -1
        
    except:
        return 0
    
def iframe(url):
    try:
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')    
        no_of_iframe =0
        for iframe in soup.find_all(r'<iframe'):
            no_of_iframe = no_of_iframe + 1    

        if(no_of_iframe != 0):
            return 1
        else:
            return -1       
        
    except:
        return 0
    
def age_of_domain(url):
    try:
        w = whois.whois(url)
        start_date = w.creation_date
        current_date = datetime.datetime.now()
        age =(current_date-start_date).days
        if(age>=180):
            return -1
        else:
            return 1
    except Exception as e:
        return 0

def dns(url):
    try:
        sd, d, s = extract(url)
        out = d + '.' + s;
        w = whois.whois(url)
        if(type(w.domain_name) is list):
            if((out.upper() in w.domain_name) or out.lower() in w.domain_name):
                return -1
            else:
                return 1
        elif((out.upper() == w.domain_name) or out.lower() == w.domain_name):
            return -1
        else:
            return 1
    except:
        return 1

def web_traffic(url):
    try:
        sd, d, s = extract(url)
        out = d + '.' + s
        link1 = 'https://ahrefs.com/blog/most-visited-websites/'
        opener = urllib.request.urlopen(link1).read()
        soup = BeautifulSoup(opener, 'lxml')
        t1 = soup.find('table', attrs = {'id':'tablepress-77'}).find('tbody')
        c = 0
        for tr in t1.find_all("tr"):
            for td in tr.find_all("td"):
                if(out == td.text):
                    c = c + 1
        if(c > 0):
            return -1
        else:
            return 1
    except:
        return 0

def page_rank(url):
    return 0

def google_index(url):
    return 0


def links_pointing(url):
    return 0

def statistical(url):
    try:
        subDomain, domain, suffix = extract(url)
        lt = ["creeksideshowstable", "altervista", "sendmaui", "seriport", "bjcurio", "118bm", "esphc", 
              "paypal-system", "remorquesfranc", "esy", "hol", "000webhostapp", "16mb", "raymannag", ]
        ln = len(lt)
        
        if( domain in lt):
            return 1
        else:
            return -1
    except:
        return 0

def testData(url):
    check = [[url_having_ip(url),url_length(url),url_short(url),having_at_symbol(url), doubleSlash(url),prefix_suffix(url),sub_domain(url),
    SSLfinal_State(url), domain_registration(url),favicon(url),port(url),https_token(url),request_url(url), url_of_anchor(url),
    Links_in_tags(url),sfh(url),email_submit(url),abnormal_url(url), redirect(url),on_mouseover(url),rightClick(url),popup(url),iframe(url),
    age_of_domain(url),dns(url),web_traffic(url),page_rank(url),google_index(url),links_pointing(url),statistical(url)]]
    print(check)
    return check

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict',methods=['GET', 'POST'])
def predict():

    if (request.method == "POST"):
        inp = request.form
        url = inp['URL']
        print(url)
        print(type(url))
        print(len(url))
        final = testData(url)
        prediction = model.predict(final)
        print(prediction)
        if(prediction == -1):
            return render_template('index.html', prediction_text='No Worries! This Website is legitimate')
        if(prediction == 1):
            return render_template('index.html', prediction_text='This is Phishing Website! BE ALERT!')

if __name__ == "__main__":
    app.run(debug=False)