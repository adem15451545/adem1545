#!/bin/bash

# Renk kodları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Root kontrolü
if [ "$(id -u)" -eq 0 ]; then
    echo -e "${RED}Hata: Bu script root olarak çalıştırılmamalıdır.${NC}"
    exit 1
fi

clear

# Başlık ve bilgi
echo -e "${CYAN}"
echo "╔════════════════════════════════════╗"
echo "║                                    ║"
echo "║        ᴀᴅᴇᴍ1545          ║"
echo "║                                    ║"
echo "╚════════════════════════════════════╝"
echo -e "${NC}"
echo -e "${YELLOW}▶ YouTube: youtube.com/@stickwar1545${NC}"
echo -e "${YELLOW}▶ GitHub: github.com/adem15451545${NC}"
sleep 2

# Paket kurulumu
echo -e "${CYAN}[1/4] Gereken paketler kuruluyor...${NC}"
pkg update -y > /dev/null 2>&1
pkg install -y git python figlet wget > /dev/null 2>&1

# Proje indirme
echo -e "${CYAN}[2/4] Proje indiriliyor...${NC}"
if [ -d "adem1545" ]; then
    rm -rf adem1545
fi

git clone https://github.com/adem15451545/adem1545.git > /dev/null 2>&1

if [ ! -d "adem1545" ]; then
    echo -e "${RED}Hata: Proje indirilemedi! İnternet bağlantınızı kontrol edin.${NC}"
    exit 1
fi

# Gerekli kütüphaneler
echo -e "${CYAN}[3/4] Python kütüphaneleri kontrol ediliyor...${NC}"
cd adem1545
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt > /dev/null 2>&1
fi

# Çalıştırma
echo -e "${CYAN}[4/4] Program başlatılıyor...${NC}"
sleep 2
clear

if [ -f "adem1545.py" ]; then
    # Logo gösterimi
    echo -e "${CYAN}"
    figlet "ADEM1545"
    echo -e "${NC}"
    echo -e "${GREEN}Başarıyla kuruldu ve başlatıldı!${NC}"
    echo ""
    
    # Programı çalıştır
    python adem1545.py
else
    echo -e "${RED}Hata: adem1545.py dosyası bulunamadı!${NC}"
    echo -e "${YELLOW}Lütfen GitHub deposunu kontrol edin: https://github.com/adem15451545/adem1545${NC}"
fi