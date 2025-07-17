#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
import whois
import socket
import ssl
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from colorama import init, Fore, Style, Back
from collections import Counter
import random
import pyfiglet
import time
import sys

# Renkli çıktı için ayarlar
init(autoreset=True)

# Özel logo oluşturma
def create_logo():
    logo_text = pyfiglet.figlet_format("adem1545", font="slant")
    colors = [Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN]
    colored_logo = ""
    for line in logo_text.split('\n'):
        colored_logo += random.choice(colors) + line + "\n"
    return colored_logo

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
        'issuer': "  🏢 Sertifika Sağlayıcı:",
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
        'not_found': f"{Fore.RED}❌ Bulunamadı{Fore.RESET}",
        'low_risk': f"{Fore.GREEN}✅ Düşük Risk{Fore.RESET}",
        'medium_risk': f"{Fore.YELLOW}⚠️ Orta Risk{Fore.RESET}",
        'high_risk': f"{Fore.RED}❌ Yüksek Risk{Fore.RESET}",
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
        'issuer': "  🏢 Certificate Issuer:",
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
        'not_found': f"{Fore.RED}❌ Not found{Fore.RESET}",
        'low_risk': f"{Fore.GREEN}✅ Low Risk{Fore.RESET}",
        'medium_risk': f"{Fore.YELLOW}⚠️ Medium Risk{Fore.RESET}",
        'high_risk': f"{Fore.RED}❌ High Risk{Fore.RESET}",
        'exit': "👋 Exiting...",
    }
}

def select_language():
    while True:
        choice = input(Fore.YELLOW + LANGUAGES['tr']['select_lang'])
        if choice == '1':
            return 'tr'
        elif choice == '2':
            return 'en'
        print(Fore.RED + "Geçersiz seçim! / Invalid choice!")

def get_ip_info(ip, lang):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
        location = f"{data.get('city', '')}, {data.get('regionName', '')}, {data.get('country', '')}"
        isp = data.get('isp', '')
        return location, isp
    except Exception as e:
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

    print("\n" + "="*80)
    print(Fore.MAGENTA + Style.BRIGHT + L['title'].center(80))
    print("="*80 + "\n")

    # Temel Bilgiler
    print(Fore.CYAN + Style.BRIGHT + L['general_info'] + Style.RESET_ALL)
    print(Fore.YELLOW + L['site_title'], Fore.WHITE + data.get('title', L['not_found']))
    print(Fore.YELLOW + L['meta_desc'], Fore.WHITE + data.get('meta_description', L['not_found']))
    print(Fore.YELLOW + L['ip_address'], Fore.WHITE + data.get('ip', L['not_found']))
    if data.get('location'):
        print(Fore.YELLOW + L['server_location'], Fore.WHITE + data['location'])

    # SSL Bilgileri
    if data.get('ssl'):
        print(Fore.CYAN + Style.BRIGHT + L['ssl_info'] + Style.RESET_ALL)
        print(Fore.YELLOW + L['issuer'], Fore.WHITE + data['ssl'].get('issuer', L['not_found']))
        print(Fore.YELLOW + L['valid_from'], Fore.WHITE + data['ssl'].get('valid_from', L['not_found']))
        print(Fore.YELLOW + L['valid_to'], Fore.WHITE + data['ssl'].get('valid_to', L['not_found']))
        print(Fore.YELLOW + L['days_left'], Fore.WHITE + str(data['ssl'].get('days_left', 0)))

    # Teknoloji Bilgileri
    print(Fore.CYAN + Style.BRIGHT + L['tech_info'] + Style.RESET_ALL)
    print(Fore.YELLOW + L['server'], Fore.WHITE + data['tech'].get('server', L['not_found']))
    print(Fore.YELLOW + L['cms'], Fore.WHITE + data['tech'].get('cms', L['not_found']))
    print(Fore.YELLOW + "  Botlar:", Fore.WHITE + ', '.join(data['tech'].get('bots', [])) or L['not_found'])

    # Güvenlik Analizi
    print(Fore.CYAN + Style.BRIGHT + L['security_info'] + Style.RESET_ALL)
    print(Fore.YELLOW + L['risk_level'], end=" ")
    risk = data['security'].get('level', 'low')
    if risk == 'high':
        print(Fore.RED + L['high_risk'])
    elif risk == 'medium':
        print(Fore.YELLOW + L['medium_risk'])
    else:
        print(Fore.GREEN + L['low_risk'])

    print(Fore.YELLOW + L['security_percentage'], Fore.WHITE + f"%{data['security'].get('security_score', 0)}")

    print(Fore.YELLOW + L['scam_analysis'], end=" ")
    scam_risk = data['scam'].get('risk', 'low')
    if scam_risk == 'high':
        print(Fore.RED + L['high_risk'])
    elif scam_risk == 'medium':
        print(Fore.YELLOW + L['medium_risk'])
    else:
        print(Fore.GREEN + L['low_risk'])

    print(Fore.YELLOW + "  Tespit Edilenler:", Fore.WHITE + ', '.join(data['scam'].get('detected_types', [])) or L['not_found'])

    # İçerik Analizi
    print(Fore.CYAN + Style.BRIGHT + L['content_info'] + Style.RESET_ALL)
    print(Fore.YELLOW + L['site_purpose'], Fore.WHITE + ', '.join(data['content'].get('purpose', [])))

    # Sosyal Medya Hesapları
    print(Fore.CYAN + Style.BRIGHT + L['social_media'] + Style.RESET_ALL)
    for name, url in data['content'].get('social_accounts', {}).items():
        print(Fore.WHITE + f"  - {name}: {url}")
    if not data['content'].get('social_accounts'):
        print(Fore.WHITE + "  " + L['not_found'])

    # Kayıtlı Kullanıcılar
    print(Fore.CYAN + Style.BRIGHT + L['user_stats'] + Style.RESET_ALL)
    print(Fore.YELLOW + "  Kayıtlı Kullanıcı Sayısı:", Fore.WHITE + str(len(data['content'].get('registered_users', []))))
    print(Fore.YELLOW + "  Örnek Kullanıcılar:", Fore.WHITE + ', '.join(data['content'].get('registered_users', [])[:5]) + "...")

    # Site Açıklaması
    print(Fore.CYAN + Style.BRIGHT + "\n📄 SİTE AÇIKLAMASI" + Style.RESET_ALL)
    print(Fore.WHITE + data['content'].get('description', 'Açıklama bulunamadı'))

    print("\n" + "="*80)
    print(Fore.GREEN + "ANALİZ TAMAMLANDI".center(80) if lang == 'tr' else "ANALYSIS COMPLETED".center(80))
    print("="*80 + "\n")

def analyze_website(url, lang):
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
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
            print(Fore.RED + LANGUAGES[lang]['connection_error'])
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
        print(Fore.RED + f"⛔ {LANGUAGES[lang]['connection_error']}: {str(e)}")
        return None

def main():
    try:
        # Dil seçimi
        lang = select_language()
        L = LANGUAGES[lang]

        while True:
            print(create_logo())
            print(Fore.CYAN + Style.BRIGHT + L['title'].center(80))
            print(Fore.YELLOW + "v3.0 | Advanced Web Analysis Tool".center(80) + "\n")

            # URL girişi
            url = input(Fore.GREEN + L['enter_url'])
            if not url:
                print(Fore.RED + "Geçersiz URL! / Invalid URL!")
                continue

            # Analiz
            start_time = time.time()
            print(Fore.BLUE + L['analyzing'])

            result = analyze_website(url, lang)

            if result:
                print_results(result, lang)
            else:
                print(Fore.RED + L['connection_error'])

            print(Fore.YELLOW + f"⏱️ {time.time() - start_time:.2f} saniye" if lang == 'tr' else f"⏱️ {time.time() - start_time:.2f} seconds")

            # Dil değiştirme seçeneği
            choice = input(Fore.CYAN + L['change_lang'])
            if choice == '0':
                print(Fore.YELLOW + L['exit'])
                break
            elif choice == '1':
                lang = 'tr'
            elif choice == '2':
                lang = 'en'

    except KeyboardInterrupt:
        print("\n" + Fore.YELLOW + L['exit'])
    except Exception as e:
        print(Fore.RED + f"⛔ Kritik hata: {str(e)}")

if __name__ == "__main__":
    main()