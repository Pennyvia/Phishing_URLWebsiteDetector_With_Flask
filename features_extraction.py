import re
import datetime
import certifi
from bs4 import BeautifulSoup
# import numpy as np
import requests
import whois
import ipaddress
import urllib
import urllib.request
import dns.resolver
import ssl
import socket
from urllib.parse import urlparse
from favicon import favicon
from tldextract import extract


# If the domain part of URL has IP address, the value assigned to this feature is 1 (phishing) or else 0 (legitimate).
def having_IP_Address(url):
    """Check if the URL contains an IP address."""
    try:
        ipaddress.ip_address(url)
        ip = -1
    except:
        ip = 1
    return ip


# If the length of URL >= 54 , the value assigned to this feature is -1 (phishing) or else 1 (legitimate).
def URL_Length(url):
    """Check if the URL exceeds a reasonable length."""
    if len(url) < 54:
        length = -1
    else:
        length = 1
    return length


shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"


# If the URL is using Shortening Services, the value assigned to this feature is -1 (phishing) or else 1 (legitimate).
def Shortining_Service(url):
    match = re.search(shortening_services, url)
    if match:
        return -1
    else:
        return 1


# If the URL has '@' symbol, the value assigned to this feature is -1 (phishing) or else 1 (legitimate).
def having_At_Symbol(url):
    """Check if the URL contains '@' symbols."""
    if "@" in url:
        at = -1
    else:
        at = 1
    return at


# If the "//" is anywhere in the URL apart from after the protocol,the value assigned to this feature is -1 (
# phishing) or else 1 (legitimate).

def double_slash_redirecting(url):
    pos = url.rfind('//')
    if pos > 6:
        if pos > 7:
            return -1
        else:
            return 1
    else:
        return 1


# Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
def Prefix_Suffix(url):
    if '-' in urlparse(url).netloc:
        return -1  # phishing
    else:
        return 1  # legitimate


def having_Sub_Domain(url):
    """If the url has more than 3 dots then it is a phishing"""
    if url.count(".") < 3:
        return 1  # legitimate
    elif url.count(".") == 3:
        return 1  # suspicious
    else:
        return 1  # phishing


def SSLfinal_State(url):
    """Check if the SSL certificate is valid for a given URL."""
    try:
        components = urlparse(url)
        domain = components.netloc
        if components.scheme not in ("https", "http"):
            raise ValueError("Only supports HTTP and HTTPS schemes")

        sock = socket.create_connection((domain, 443))
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        wrapped_sock = ssl_context.wrap_socket(sock, server_hostname=domain)

        if isinstance(wrapped_sock.getpeercert(), tuple):
            return 1
        else:
            peername = wrapped_sock.getpeercert()
            issuer = peername.get("issuer", {}).get("commonName", "")
            subject = peername.get("subject", {}).get("commonName", "")

            if domain not in subject or domain != subject:
                return 1

            if domain in peername.get("subjectAltName", []) or domain in issuer:
                return -1
            else:
                return 1

    except Exception as e:
        print(f"SSL verification failed: {e}")
        return -1


def Domain_registeration_length(url):
    dns = 0
    try:
        domain_name = whois.whois(urlparse(url).netloc)
    except:
        dns = 1

    if dns == 1:
        return -1  # phishing
    else:
        expiration_date = domain_name.expiration_date
        today = datetime.datetime.now()
        if expiration_date is None:
            return -1
        elif type(expiration_date) is list or type(today) is list:
            return -1
        else:
            creation_date = domain_name.creation_date
            expiration_date = domain_name.expiration_date
            if (isinstance(creation_date, str) or isinstance(expiration_date, str)):
                try:
                    creation_date = datetime.datetime.strptime(creation_date, '%Y-%m-%d %H:%M:%S')
                    expiration_date = datetime.datetime.strptime(expiration_date, "%Y-%m-%d %H:%M:%S")
                except:
                    return 0
            registration_length = abs((expiration_date - today).days)
            if registration_length / 365 <= 1:
                return -1  # phishing
            else:
                return 1  # legitimate


def Favicon(url):
    """Check if the favicon is present and matches the domain."""
    try:
        icons = favicon.get(url)
        icon = icons[0]
        extracted_url = extract(icon.url)
        icon_domain = extracted_url.domain
        extracted_url = extract(url)
        url_domain = extracted_url.domain
        if icon_domain == url_domain:
            return -1
        else:
            return 1
    except:
        return 1


def port(url):
    try:
        a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        location = (url[7:], 80)
        result_of_check = a_socket.connect_ex(location)
        if result_of_check == 0:
            a_socket.close()
            return 1
        location = (url[7:], 443)
        result_of_check = a_socket.connect_ex(location)
        if result_of_check == 0:
            a_socket.close()
            return 1
        a_socket.close()
        return -1  # phishing
    except:
        return -1  # phishing


# Existence of “HTTPS” Token in the Domain Part of the URL (https_Domain)
def HTTPS_token(url):
    domain = urlparse(url).netloc
    if 'https' in domain:
        return -1  # phishing
    else:
        return 1  # legitimate


def Request_URL(url):
    try:
        subDomain, domain, suffix = extract(url)
        websiteDomain = domain

        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        imgs = soup.findAll('img', src=True)
        total = len(imgs)

        linked_to_same = 0
        avg = 0
        for image in imgs:
            subDomain, domain, suffix = extract(image['src'])
            imageDomain = domain
            if (websiteDomain == imageDomain or imageDomain == ''):
                linked_to_same = linked_to_same + 1
        vids = soup.findAll('video', src=True)
        total = total + len(vids)

        for video in vids:
            subDomain, domain, suffix = extract(video['src'])
            vidDomain = domain
            if (websiteDomain == vidDomain or vidDomain == ''):
                linked_to_same = linked_to_same + 1
        linked_outside = total - linked_to_same
        if (total != 0):
            avg = linked_outside / total

        if (avg < 0.22):
            return 1  # legitimate
        else:
            return -1  # phishing
    except:
        return -1  # phishing


def URL_of_Anchor(url):
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
            if (websiteDomain == anchorDomain or anchorDomain == ''):
                linked_to_same = linked_to_same + 1
        linked_outside = total - linked_to_same
        if (total != 0):
            avg = linked_outside / total

        if (avg < 0.31):
            return 1
        elif (0.31 <= avg <= 0.67):
            return 1
        else:
            return -1  # phishing
    except:
        return 1


def Links_in_tags(url):
    try:
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')

        no_of_meta = 0
        no_of_link = 0
        no_of_script = 0
        anchors = 0
        avg = 0
        for meta in soup.find_all('meta'):
            no_of_meta = no_of_meta + 1
        for link in soup.find_all('link'):
            no_of_link = no_of_link + 1
        for script in soup.find_all('script'):
            no_of_script = no_of_script + 1
        for anchor in soup.find_all('a'):
            anchors = anchors + 1
        total = no_of_meta + no_of_link + no_of_script + anchors
        tags = no_of_meta + no_of_link + no_of_script
        if (total != 0):
            avg = tags / total

        if (avg < 0.25):
            return 1  # legitimate
        elif (0.25 <= avg <= 0.81):
            return 0  # suspicious
        else:
            return -1  # phishing
    except:
        return 0  # suspicious


def SFH(url):
    try:
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')

        sfh_tags = soup.find_all('form', action=True)
        for tag in sfh_tags:
            action = tag['action']
            if action == '' or action == 'about:blank':
                return -1  # Phishing
            else:
                parsed_url = urllib.parse.urlparse(action)
                if parsed_url.netloc != urllib.parse.urlparse(url).netloc:
                    return 0  # Suspicious
        return 1  # Legitimate
    except:
        return 0  # Suspicious


def Submitting_to_email(url):
    try:
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        if (soup.find('mailto:', 'mail():')):
            return -1  # Phishing
        else:
            return 1  # legitimate
    except:
        return -1  # phishing


def Abnormal_URL(url):
    try:
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        w = whois.whois(domain)
        if w.domain_name != domain:
            return -1  # Phishing
        else:
            return 1  # Legitimate
    except:
        return 0  # Suspicious


def Redirect(url):
    redirect_count = 0
    visited_urls = set()
    while url not in visited_urls:
        visited_urls.add(url)
        try:
            response = requests.get(url, allow_redirects=False)
            if response.status_code == 301 or response.status_code == 302:
                url = response.headers['Location']
                redirect_count += 1
            else:
                break
        except:
            return 0  # Suspicious
    if redirect_count <= 1:
        return 1  # Legitimate
    elif redirect_count >= 2 and redirect_count < 4:
        return 0  # Suspicious
    else:
        return -1  # Phishing


def on_mouseover(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            if response.text == "":
                return 1  # Legitimate
            else:
                if re.findall("event.button==2", response.text):
                    return -1  # Phishing
                else:
                    return 1  # Legitimate
        else:
            return 0  # Suspicious
    except:
        return 0  # Suspicious


# right click disabled = (-1) phishing otherwise legitimate
def RightClick(url):
    try:
        response = requests.get(url)
        source_code = response.text
        if 'event.button==2' in source_code:
            return -1  # Phishing
        else:
            return 1  # Legitimate
    except:
        return 0  # Suspicious


def popUpWidnow(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            popup_window = soup.find('div', {'id': 'popup-window'})
            if popup_window:
                text_fields = popup_window.find_all('input', {'type': 'text'})
                if text_fields:
                    return -1  # Phishing
                else:
                    return 1  # Legitimate
            else:
                return 1  # Legitimate
        else:
            return 0  # Suspicious
    except:
        return 0  # Suspicious


def Iframe(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            iframes = soup.find_all('iframe')
            for iframe in iframes:
                if iframe.get('frameBorder') is None:
                    return -1  # Phishing
            return 1  # Legitimate
        else:
            return 0  # Suspicious
    except:
        return 0  # Suspicious


def age_of_domain(url):
    dns = 0
    try:
        domain_name = whois.whois(urlparse.urlparse(url).netloc)
    except:
        dns = 1

    if dns == 1:
        return 1
    else:
        creation_date = domain_name.creation_date
        expiration_date = domain_name.expiration_date
        if (isinstance(creation_date, str) or isinstance(expiration_date, str)):
            try:
                creation_date = datetime.datetime(creation_date, '%Y-%m-%d')
                expiration_date = datetime.datetime(expiration_date, "%Y-%m-%d")
            except:
                return 2
        if ((expiration_date is None) or (creation_date is None)):
            return 1
        elif ((type(expiration_date) is list) or (type(creation_date) is list)):
            return 2
        else:
            age_of_domain = abs((expiration_date - creation_date).days)
            if (age_of_domain / 30) < 6:
                return -1  # phishing
            else:
                return 1  # legitimate


def DNSRecord(url):
    domain = urlparse(url).netloc
    try:
        answers = dns.resolver.query(domain, 'A')
        return 1  # legitimate
    except dns.resolver.NXDOMAIN:
        return -1  # PHISHING
    except dns.resolver.NoNameservers:
        return -1
    except dns.resolver.NoAnswer:
        return -1


def web_traffic(url):
    def get_alexa_rank(domain):
        try:
            response = requests.get(f'https://www.alexa.com/siteinfo/{domain}')
            rank = int(response.text.split('<span class="big">')[1].split('</')[0].replace(',', ''))
            return rank
        except Exception:
            return None

    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    rank = get_alexa_rank(domain)
    if rank is not None and rank < 100000:
        return 1  # legitimate
    elif rank is not None and rank >= 100000:
        return 0  # Suspicious
    else:
        return -1  # phishing


def Page_Rank(url):
    # Send a GET request to the URL and parse the HTML content
    try:
        response = requests.get(url, verify=False)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            if soup.find('meta', {'name': 'pr'}):
                return 1  # Legitimate
            else:
                return -1  # Phishing
        else:
            return 0  # Suspicious

    except:
        return 0  # Suspicious


def Google_Index(url):
    # Send a GET request to the URL and parse the HTML content
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')

    # Check if the website is indexed by Google by looking for a Google-specific meta tag
    meta_tags = soup.find_all('meta')
    for meta in meta_tags:
        if 'name' in meta.attrs and meta['name'] == 'googlebot':
            return 1  # legitimate

    return -1  # phishing


def Links_pointing_to_page(url):
    # Send a GET request to the URL and parse the HTML content
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')

    # Count the number of links pointing to the webpage
    links = soup.find_all('a')
    num_links = 0
    for link in links:
        href = link.get('href')
        if href is not None and href != '' and href != url:
            num_links += 1

    # Classify the website based on the number of links pointing to it
    if num_links == 0:
        return -1  # phishing
    elif num_links > 0 and num_links <= 2:
        return 0
    else:
        return 1  # legitimate


def Statistical_report(url):
    # Send a GET request to the PhishTank API to check if the domain or IP is in the top 10 phishing domains or IPs
    parsed_url = urllib.parse.urlparse(url)
    domain = parsed_url.netloc
    ip = socket.gethostbyname(domain)

    try:
        response = requests.get(f'https://checkurl.phishtank.com/checkurl/index.php?url={url}&format=json')
        data = response.json()
        if data['results']['overall_result'] == 'Suspicious':
            return -1  # phishing
    except requests.exceptions.JSONDecodeError:
        return 1  # legitimate (assuming the URL is legitimate if the response is not in JSON format)

    # Check if the IP is in the top 50 phishing IPs according to StopBadware
    with open('stopbadware_ips.txt', 'r') as f:
        for line in f:
            if ip == line.strip():
                return -1  # phishing

    # Check if the domain or IP is in the top 10 phishing domains or IPs according to PhishTank
    try:
        response = requests.get(f'https://checkurl.phishtank.com/checkurl/index.php?url={domain}&format=json')
        data = response.json()
        if data['results']['overall_result'] == 'Suspicious':
            return -1  # Phishing
    except requests.exceptions.JSONDecodeError:
        return 1  # legitimate (assuming the URL is legitimate if the response is not in JSON format)

    try:
        response = requests.get(f'https://checkurl.phishtank.com/checkurl/index.php?url={ip}&format=json')
        data = response.json()
        if data['results']['overall_result'] == 'Suspicious':
            return -1  # phishing
    except requests.exceptions.JSONDecodeError:
        return 1  # legitimate (assuming the URL is legitimate if the response is not in JSON format)

    return 1  # legitimated


def extract_features(url):
    features = [
        having_IP_Address(url),
        URL_Length(url),
        Shortining_Service(url),
        having_At_Symbol(url),
        double_slash_redirecting(url),
        Prefix_Suffix(url),
        having_Sub_Domain(url),
        SSLfinal_State(url),
        Domain_registeration_length(url),
        Favicon(url),
        port(url),
        HTTPS_token(url),
        Request_URL(url),
        URL_of_Anchor(url),
        Links_in_tags(url),
        SFH(url),
        Submitting_to_email(url),
        Abnormal_URL(url),
        Redirect(url),
        on_mouseover(url),
        RightClick(url),
        popUpWidnow(url),
        Iframe(url),
        age_of_domain(url),
        DNSRecord(url),
        web_traffic(url),
        Page_Rank(url),
        Google_Index(url),
        Links_pointing_to_page(url),
        Statistical_report(url)
    ]
    return features


print("features retained successfully")
