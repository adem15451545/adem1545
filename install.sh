#!/bin/bash

# Gerekli paketlerin kurulumu
apt-get update -qq > /dev/null
apt install python3 git figlet -y > /dev/null

clear
sleep 2

# Logo ve bilgi
echo -e "\e[96m"
figlet "ᴀᴅᴇᴍ1545"
echo -e "\e[0m"
echo -e "\e[96mʙʏ ᴀᴅᴇᴍ1545\e[0m"
sleep 2

# Sosyal medya bilgileri (isteğe bağlı)
echo -e "\e[96mTikTok   :\e[0m https://tiktok.com/@ademyalcin444"
echo -e "\e[96mInstagram:\e[0m https://www.instagram.com/adema1545"
echo -e "\e[96mYouTube  :\e[0m https://youtube.com/@stickwar1545"
echo -e "\e[96mGitHub   :\e[0m https://github.com/adem15451545"
echo -e "\e[96mSite     :\e[0m https://adem1545.godaddysites.com/"
echo -e "\e[96mTelegram :\e[0m https://t.me/+DmSJcq5izrdiOTY0"
sleep 2

# Projenin yüklenmesi
echo -e "\e[96m[PROJE İNDİRİLİYOR]\e[0m"
git clone https://github.com/adem15451545/-1545.git > /dev/null 2>&1

# Klasöre girip çalıştırma
if [ -d "adem1545" ]; then
    cd adem1545
    echo -e "\e[96m[ÇALIŞTIRILIYOR]\e[0m"
    python3 adem1545.py
else
    echo -e "\e[91mKlasör bulunamadı! Repo yanlış ya da isim hatalı.\e[0m"
fi