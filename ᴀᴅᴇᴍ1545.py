#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import requests
import re
import socket
import ssl
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from collections import Counter
import random
import time
import sys

# Termux için ANSI renk kodları
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'  # PURPLE yerine MAGENTA kullanıyoruz
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    BG_BLACK = '\033[40m'
    LIGHT_BLUE = '\033[94m'  # LIGHT_BLUE eklendi

def create_logo():
    # Ana logo (retro renklerde)
    colors = [Colors.RED, Colors.CYAN, Colors.GREEN, Colors.MAGENTA]  # PURPLE yerine MAGENTA
    logo = r"""
    █▀▀▀▀▀▀▀▀█ █▀▀▀▀▀▀▀█ █▀▀▀▀▀▀▀▀█ ▀▀█▀▀ █▀▀▀▀▀▀▀█
    █ █▀▀▀▀▀ █ █      █ █ █▀▀▀▀▀ █   █   █      █
    █ █   █  █ █▀▀▀▀▀▀▀█ █ █   █  █   █   █▀▀▀▀▀▀▀█
    █ █   █  █ █      █ █ █   █  █   █   █      █
    █ █   █  █ █      █ █ █   █  █   █   █      █
    █ █   █  █ █      █ █ █   █  █   █   █      █
    
    ░█░█░█▀▀░█▀█░█▀▀░█▀▀░█▀▀░█▀▀
    ░█░█░█▀▀░█░█░█▀▀░█▀▀░█▀▀░█▀▀
    ░▀▀▀░▀▀▀░▀░▀░▀▀▀░▀░░░▀▀▀░▀▀▀
    """
    
    # ʙʏ ᴀᴅᴇᴍ1545 yazısı (açık mavi ve yazı stili)
    signature = Colors.LIGHT_BLUE + r"""
╔════════════════════════════════════╗
║                                    ║
║        ᴀᴅᴇᴍ1545                   ║
║                                    ║
╚════════════════════════════════════╝
    """ + Colors.RESET
    
    return random.choice(colors) + logo + signature
    
# Dil desteği
LANGUAGES = {
    'tr': {
        'title': "ADEM1545 GELİŞMİŞ WEB ANALİZ PANELİ",
        'select_lang': "Dil seçiniz (1-Türkçe, 2-English): ",
        'change_lang': "\nDil değiştirmek için: 1-Türkçe, 2-English, 0-Çıkış: ",
        'enter_url': "🔗 Analiz edilecek site URL'sini girin (örn: https://www.ornek.com): ",
        'analyzing': "🔍 Site analiz ediliyor, lütfen bekleyin...",
        'connection_error': "⚠️ Siteye bağlanılamadı!",
        'general_info': "\n📌 TEMEL BİLGİLER",
        'site_title': "  📝 Site Başlığı:",
        'meta_desc': "  📄 Açıklama:",
        'ip_address': "  🌐 IP Adresi:",
        'server_location': "  📍 Sunucu Konumu:",
        'ssl_info': "\n🔒 SSL BİLGİLERİ",
        'issuer': "  � Sertifika Sağlayıcı:",
        'valid_from': "  📅 Başlangıç Tarihi:",
        'valid_to': "  📅 Bitiş Tarihi:",
        'days_left': "  ⏳ Kalan Gün:",
        'tech_info': "\n🛠️ TEKNOLOJİ BİLGİLERİ",
        'server': "  💻 Sunucu:",
        'cms': "  🖥️ CMS:",
        'programming_lang': "  💾 Programlama Dili:",
        'security_info': "\n🛡️ GÜVENLİK ANALİZİ",
        'risk_level': "  ☢️ Risk Seviyesi:",
        'security_percentage': "  🔐 Güvenlik Skoru:",
        'scam_analysis': "  🕵️ Dolandırıcılık Analizi:",
        'malicious_links': "  ⚠️ Şüpheli Linkler:",
        'admin_panels': "\n🔑 YÖNETİM PANELLERİ",
        'content_info': "\n📊 İÇERİK ANALİZİ",
        'top_keywords': "  🔑 Anahtar Kelimeler:",
        'social_media': "\n📱 SOSYAL MEDYA HESAPLARI",
        'file_analysis': "\n📁 DOSYA ANALİZİ",
        'apk_files': "  📦 APK Dosyaları:",
        'archive_files': "  🗄️ Arşiv Dosyaları:",
        'site_purpose': "\n🎯 SİTE AMACI",
        'user_stats': "\n👥 KULLANICI İSTATİSTİKLERİ",
        'registration_methods': "\n🔐 KAYIT YÖNTEMLERİ",
        'server_vulns': "\n⚠️ SUNUCU AÇIKLIKLARI",
        'financial_info': "\n💲 FİNANSAL BİLGİLER",
        'update_info': "\n🔄 GÜNCELLEME BİLGİLERİ",
        'admin_stats': "\n👨‍💻 ADMIN BİLGİLERİ",
        'hack_stats': "\n💀 HACK İSTATİSTİKLERİ",
        'not_found': "❌ Bulunamadı",
        'low_risk': "✅ Düşük Risk",
        'medium_risk': "⚠️ Orta Risk",
        'high_risk': "❌ Yüksek Risk",
        'exit': "👋 Çıkılıyor...",
    },
    'en': {
        'title': "ADEM1545 ADVANCED WEB ANALYSIS PANEL",
        'select_lang': "Select language (1-Turkish, 2-English): ",
        'change_lang': "\nTo change language: 1-Turkish, 2-English, 0-Exit: ",
        'enter_url': "🔗 Enter website URL to analyze (ex: https://www.example.com): ",
        'analyzing': "🔍 Analyzing website, please wait...",
        'connection_error': "⚠️ Could not connect to the site!",
        'general_info': "\n📌 BASIC INFORMATION",
        'site_title': "  📝 Site Title:",
        'meta_desc': "  📄 Description:",
        'ip_address': "  🌐 IP Address:",
        'server_location': "  📍 Server Location:",
        'ssl_info': "\n🔒 SSL INFORMATION",
        'issuer': "  � Certificate Issuer:",
        'valid_from': "  📅 Valid From:",
        'valid_to': "  📅 Valid To:",
        'days_left': "  ⏳ Days Left:",
        'tech_info': "\n🛠️ TECHNOLOGY INFORMATION",
        'server': "  💻 Server:",
        'cms': "  🖥️ CMS:",
        'programming_lang': "  💾 Programming Language:",
        'security_info': "\n🛡️ SECURITY ANALYSIS",
        'risk_level': "  ☢️ Risk Level:",
        'security_percentage': "  🔐 Security Score:",
        'scam_analysis': "  🕵️ Scam Analysis:",
        'malicious_links': "  ⚠️ Suspicious Links:",
        'admin_panels': "\n🔑 ADMIN PANELS",
        'content_info': "\n📊 CONTENT ANALYSIS",
        'top_keywords': "  🔑 Top Keywords:",
        'social_media': "\n📱 SOCIAL MEDIA ACCOUNTS",
        'file_analysis': "\n📁 FILE ANALYSIS",
        'apk_files': "  📦 APK Files:",
        'archive_files': "  🗄️ Archive Files:",
        'site_purpose': "\n🎯 SITE PURPOSE",
        'user_stats': "\n👥 USER STATISTICS",
        'registration_methods': "\n🔐 REGISTRATION METHODS",
        'server_vulns': "\n⚠️ SERVER VULNERABILITIES",
        'financial_info': "\n💲 FINANCIAL INFO",
        'update_info': "\n🔄 UPDATE INFORMATION",
        'admin_stats': "\n👨‍💻 ADMIN INFORMATION",
        'hack_stats': "\n💀 HACK STATISTICS",
        'not_found': "❌ Not found",
        'low_risk': "✅ Low Risk",
        'medium_risk': "⚠️ Medium Risk",
        'high_risk': "❌ High Risk",
        'exit': "👋 Exiting...",
    }
}

def select_language():
    while True:
        choice = input(Colors.YELLOW + LANGUAGES['tr']['select_lang'])
        if choice == '1':
            return 'tr'
        elif choice == '2':
            return 'en'
        print(Colors.RED + "Geçersiz seçim! / Invalid choice!")

def get_ip_info(ip, lang):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
        if data['status'] == 'success':
            location = f"{data.get('city', '')}, {data.get('regionName', '')}, {data.get('country', '')}"
            isp = data.get('isp', '')
            return location, isp
        return LANGUAGES[lang]['not_found'], LANGUAGES[lang]['not_found']
    except:
        return LANGUAGES[lang]['not_found'], LANGUAGES[lang]['not_found']

def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                valid_from = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                valid_to = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (valid_to - datetime.now()).days

                return {
                    'issuer': issuer.get('organizationName', 'Unknown'),
                    'valid_from': valid_from.strftime('%Y-%m-%d'),
                    'valid_to': valid_to.strftime('%Y-%m-%d'),
                    'days_left': days_left
                }
    except Exception as e:
        return None

def detect_technologies(response):
    tech = {
        'server': None,
        'cms': None,
        'programming_lang': None,
        'javascript_frameworks': [],
        'bots': [],
        'analytics': []
    }

    # Sunucu bilgisi
    tech['server'] = response.headers.get('Server', 'Unknown')

    # CMS tespiti
    if '/wp-content/' in response.text.lower():
        tech['cms'] = 'WordPress'
    elif 'joomla' in response.text.lower():
        tech['cms'] = 'Joomla'

    # Programlama dili tespiti
    if '<?php' in response.text.lower():
        tech['programming_lang'] = 'PHP'
    elif '<%' in response.text.lower() and '%>' in response.text.lower():
        tech['programming_lang'] = 'ASP'
    elif 'django' in response.text.lower():
        tech['programming_lang'] = 'Python/Django'

    # Bot tespiti
    if 'googlebot' in response.text.lower():
        tech['bots'].append('Google Bot')
    if 'bingbot' in response.text.lower():
        tech['bots'].append('Bing Bot')

    return tech

def analyze_scam(text, url):
    scam_keywords = {
        'free': ['money', 'credit', 'bitcoin', 'gift', 'earn'],
        'hack': ['password', 'account', 'crack', 'hack'],
        'casino': ['gambling', 'bet', 'slot', 'roulette'],
        'phishing': ['login', 'bank', 'payment'],
        'fake': ['certificate', 'diploma', 'document', 'id']
    }

    scam_score = 0
    detected_scams = []

    for category, keywords in scam_keywords.items():
        for keyword in keywords:
            if keyword in text.lower():
                scam_score += 1
                detected_scams.append(category)
                break

    # Risk seviyesi
    if scam_score > 5:
        risk = 'high'
    elif scam_score > 2:
        risk = 'medium'
    else:
        risk = 'low'

    return {
        'risk': risk,
        'score': scam_score,
        'detected_types': list(set(detected_scams)),
        'security_percentage': max(0, 100 - scam_score*10)
    }

def check_security(url, domain):
    risks = {
        'level': 'low',
        'admin_panels': [],
        'vulnerabilities': [],
        'hack_attempts': random.randint(0, 100),
        'active_admins': random.randint(1, 5),
        'inactive_admins': random.randint(0, 2),
        'security_score': 80  # Başlangıç değeri
    }

    # Admin panelleri
    admin_paths = ['/admin', '/wp-admin', '/login', '/dashboard']
    for path in admin_paths:
        try:
            response = requests.head(urljoin(url, path), timeout=5, allow_redirects=False)
            if response.status_code in [200, 301, 302]:
                risks['admin_panels'].append(f"{path} ({response.status_code})")
                risks['security_score'] -= 10
        except:
            continue

    # Güvenlik açıkları
    if risks['admin_panels']:
        risks['vulnerabilities'].append('Open admin panel')
        risks['security_score'] -= 15

    if len(risks['admin_panels']) > 2:
        risks['level'] = 'high'
    elif risks['admin_panels']:
        risks['level'] = 'medium'

    risks['security_score'] = max(0, risks['security_score'])
    return risks

def analyze_content(soup, domain, lang):
    # Sosyal medya hesapları
    social_accounts = {}
    social_platforms = {
        'instagram.com': 'Instagram',
        'tiktok.com': 'TikTok',
        'youtube.com': 'YouTube',
        'discord.gg': 'Discord',
        't.me': 'Telegram',
        'facebook.com': 'Facebook',
        'twitter.com': 'Twitter',
        'linkedin.com': 'LinkedIn'
    }

    for a in soup.find_all('a', href=True):
        for domain_sm, name in social_platforms.items():
            if domain_sm in a['href'] and name not in social_accounts:
                social_accounts[name] = a['href']

    # Site amacı
    text = soup.get_text().lower()
    purposes = []
    if 'shop' in text or 'buy' in text:
        purposes.append('E-commerce')
    if 'blog' in text or 'post' in text:
        purposes.append('Blog')

    # Kullanıcı istatistikleri (simüle)
    users = [f'user{random.randint(1, 1000)}' for _ in range(random.randint(5, 15))]

    return {
        'social_accounts': social_accounts,
        'purpose': purposes if purposes else ['General'],
        'registered_users': users,
        'last_update': datetime.now().strftime('%Y-%m-%d'),
        'description': generate_description(soup, domain, lang)
    }

def generate_description(soup, domain, lang):
    text = ' '.join(p.get_text() for p in soup.find_all(['p', 'h1', 'h2', 'h3']))
    words = re.findall(r'\b\w{4,}\b', text.lower())
    top_keywords = Counter(words).most_common(5)

    if lang == 'tr':
        desc = f"{domain} sitesi "
        if 'alışveriş' in text.lower() or 'satın al' in text.lower():
            desc += "bir e-ticaret sitesi olarak görünüyor. "
        elif 'blog' in text.lower() or 'yazı' in text.lower():
            desc += "bir blog sitesi gibi duruyor. "
        else:
            desc += "çeşitli içerikler sunan bir web sitesi. "

        desc += f"Anahtar kelimeler: {', '.join([kw[0] for kw in top_keywords])}. "

        if len(text) > 1000:
            desc += "Site oldukça kapsamlı içeriğe sahip."
        else:
            desc += "Site nispeten daha az içerik barındırıyor."
    else:
        desc = f"The {domain} website appears to be "
        if 'shop' in text.lower() or 'buy' in text.lower():
            desc += "an e-commerce site. "
        elif 'blog' in text.lower() or 'post' in text.lower():
            desc += "a blog site. "
        else:
            desc += "a general purpose website. "

        desc += f"Main keywords: {', '.join([kw[0] for kw in top_keywords])}. "

        if len(text) > 1000:
            desc += "The site has extensive content."
        else:
            desc += "The site has relatively less content."

    return desc

def print_results(data, lang):
    L = LANGUAGES[lang]

    print("\n" + "="*60)
    print(Colors.MAGENTA + Colors.BOLD + L['title'].center(60))
    print("="*60 + "\n")

    # Temel Bilgiler
    print(Colors.CYAN + Colors.BOLD + L['general_info'] + Colors.RESET)
    print(Colors.YELLOW + L['site_title'], Colors.WHITE + data.get('title', L['not_found']))
    print(Colors.YELLOW + L['meta_desc'], Colors.WHITE + data.get('meta_description', L['not_found']))
    print(Colors.YELLOW + L['ip_address'], Colors.WHITE + data.get('ip', L['not_found']))
    if data.get('location'):
        print(Colors.YELLOW + L['server_location'], Colors.WHITE + data['location'])

    # SSL Bilgileri
    if data.get('ssl'):
        print(Colors.CYAN + Colors.BOLD + L['ssl_info'] + Colors.RESET)
        print(Colors.YELLOW + L['issuer'], Colors.WHITE + data['ssl'].get('issuer', L['not_found']))
        print(Colors.YELLOW + L['valid_from'], Colors.WHITE + data['ssl'].get('valid_from', L['not_found']))
        print(Colors.YELLOW + L['valid_to'], Colors.WHITE + data['ssl'].get('valid_to', L['not_found']))
        print(Colors.YELLOW + L['days_left'], Colors.WHITE + str(data['ssl'].get('days_left', 0)))

    # Teknoloji Bilgileri
    print(Colors.CYAN + Colors.BOLD + L['tech_info'] + Colors.RESET)
    print(Colors.YELLOW + L['server'], Colors.WHITE + data['tech'].get('server', L['not_found']))
    print(Colors.YELLOW + L['cms'], Colors.WHITE + data['tech'].get('cms', L['not_found']))
    print(Colors.YELLOW + L['programming_lang'], Colors.WHITE + data['tech'].get('programming_lang', L['not_found']))
    print(Colors.YELLOW + "  Botlar:", Colors.WHITE + ', '.join(data['tech'].get('bots', [])) or L['not_found'])

    # Güvenlik Analizi
    print(Colors.CYAN + Colors.BOLD + L['security_info'] + Colors.RESET)
    print(Colors.YELLOW + L['risk_level'], end=" ")
    risk = data['security'].get('level', 'low')
    if risk == 'high':
        print(Colors.RED + L['high_risk'])
    elif risk == 'medium':
        print(Colors.YELLOW + L['medium_risk'])
    else:
        print(Colors.GREEN + L['low_risk'])

    print(Colors.YELLOW + L['security_percentage'], Colors.WHITE + f"%{data['security'].get('security_score', 0)}")

    print(Colors.YELLOW + L['scam_analysis'], end=" ")
    scam_risk = data['scam'].get('risk', 'low')
    if scam_risk == 'high':
        print(Colors.RED + L['high_risk'])
    elif scam_risk == 'medium':
        print(Colors.YELLOW + L['medium_risk'])
    else:
        print(Colors.GREEN + L['low_risk'])

    print(Colors.YELLOW + "  Tespit Edilenler:", Colors.WHITE + ', '.join(data['scam'].get('detected_types', [])) or L['not_found'])

    # İçerik Analizi
    print(Colors.CYAN + Colors.BOLD + L['content_info'] + Colors.RESET)
    print(Colors.YELLOW + L['site_purpose'], Colors.WHITE + ', '.join(data['content'].get('purpose', [])))

    # Sosyal Medya Hesapları
    print(Colors.CYAN + Colors.BOLD + L['social_media'] + Colors.RESET)
    for name, url in data['content'].get('social_accounts', {}).items():
        print(Colors.WHITE + f"  - {name}: {url}")
    if not data['content'].get('social_accounts'):
        print(Colors.WHITE + "  " + L['not_found'])

    print("\n" + "="*60)
    print(Colors.GREEN + "ANALİZ TAMAMLANDI".center(60) if lang == 'tr' else "ANALYSIS COMPLETED".center(60))
    print("="*60 + "\n")

def analyze_website(url, lang):
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        headers = {
            'User-Agent': 'Mozilla/5.0 (Linux; Android 10; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36',
            'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7'
        }

        try:
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
        except requests.exceptions.SSLError:
            url = url.replace('https://', 'http://')
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(Colors.RED + LANGUAGES[lang]['connection_error'])
            return None

        soup = BeautifulSoup(response.text, 'html.parser')
        domain = urlparse(url).netloc

        # Temel bilgiler
        result = {
            'url': url,
            'title': soup.title.string.strip() if soup.title else LANGUAGES[lang]['not_found'],
            'meta_description': None,
            'ip': None,
            'location': None,
            'ssl': None,
            'tech': {},
            'scam': {},
            'security': {},
            'content': {}
        }

        # Meta açıklama
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if meta_desc and 'content' in meta_desc.attrs:
            result['meta_description'] = meta_desc['content'].strip()

        # IP adresi ve konum bilgisi
        try:
            result['ip'] = socket.gethostbyname(domain)
            result['location'], _ = get_ip_info(result['ip'], lang)
        except socket.gaierror:
            pass

        # SSL bilgisi
        result['ssl'] = get_ssl_info(domain)

        # Teknoloji tespiti
        result['tech'] = detect_technologies(response)

        # Dolandırıcılık analizi
        result['scam'] = analyze_scam(soup.get_text(), url)

        # Güvenlik analizi
        result['security'] = check_security(url, domain)

        # İçerik analizi
        result['content'] = analyze_content(soup, domain, lang)

        return result

    except Exception as e:
        print(Colors.RED + f"⛔ {LANGUAGES[lang]['connection_error']}: {str(e)}")
        return None

def main():
    try:
        # Dil seçimi
        lang = select_language()
        L = LANGUAGES[lang]

        while True:
            print(create_logo())
            print(Colors.CYAN + Colors.BOLD + L['title'].center(60))
            print(Colors.YELLOW + "v3.0 | Termux Uyumlu".center(60) + "\n")

            # URL girişi
            url = input(Colors.GREEN + L['enter_url'])
            if not url:
                print(Colors.RED + "Geçersiz URL! / Invalid URL!")
                continue

            # Analiz
            start_time = time.time()
            print(Colors.BLUE + L['analyzing'])

            result = analyze_website(url, lang)

            if result:
                print_results(result, lang)
            else:
                print(Colors.RED + "Analiz başarısız oldu! / Analysis failed!")

            # Dil değiştirme veya çıkış
            choice = input(Colors.YELLOW + L['change_lang'])
            if choice == '0':
                print(Colors.GREEN + L['exit'])
                break
            elif choice == '1':
                lang = 'tr'
            elif choice == '2':
                lang = 'en'
            else:
                continue

    except KeyboardInterrupt:
        print("\n" + Colors.RED + LANGUAGES.get(lang, LANGUAGES['en'])['exit'])
        sys.exit(0)

if __name__ == "__main__":
    main()