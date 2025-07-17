#!/data/data/com.termux/files/usr/bin/bash

BLUE='\033[96m'
RESET='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════╗"
echo -e "║                                                                                                                  ║"
echo -e "║        ᴀᴅᴇᴍ1545                                                                                        ║"
echo -e "║                                                                                                                  ║"
echo -e "╚════════════════════════════════════╝${RESET}"

# Sosyal medya bağlantıları
echo -e "${BLUE}📱 Sosyal Medya Hesaplarım:${RESET}"
echo -e "${BLUE}📌 TikTok:     ${RESET}https://tiktok.com/@ademyalcin444"
echo -e "${BLUE}📌 Instagram:  ${RESET}https://www.instagram.com/adema1545"
echo -e "${BLUE}📌 YouTube:    ${RESET}https://youtube.com/@stickwar1545"
echo -e "${BLUE}📌 GitHub:   ${RESET}https://github.com/adem15451545"
echo -e "${BLUE}📌 GitHub:   ${RESET}https://github.com/adem15451545/-1545.git"
echo -e "${BLUE}📌 Web Site:   ${RESET}https://adem1545.godaddysites.com/"
echo -e "${BLUE}📌 Telegram:   ${RESET}https://t.me/+DmSJcq5izrdiOTY0"

REPO_URL="https://github.com/adem15451545/adem1545.git"
DIR_NAME="adem1545"
SCRIPT_NAME="ᴀᴅᴇᴍ1545.py"

if ! command -v git &> /dev/null
then
    echo -e "${BLUE}Git yüklü değil, yükleniyor...${RESET}"
    pkg update -y
    pkg install git -y
fi

if [ -d "$DIR_NAME" ]; then
    echo -e "${BLUE}$DIR_NAME klasörü zaten var. Siliniyor...${RESET}"
    # Önce izinleri aç
    chmod -R 777 "$DIR_NAME"
    # Klasörü sil
    rm -rf "$DIR_NAME"
    if [ -d "$DIR_NAME" ]; then
        echo -e "${BLUE}Klasör silinemedi. Lütfen elle silip tekrar deneyin.${RESET}"
        exit 1
    fi
fi

echo -e "${BLUE}Repo indiriliyor...${RESET}"
git clone "$REPO_URL"

cd "$DIR_NAME" || { echo "Klasöre girilemedi!"; exit 1; }

chmod +x "$SCRIPT_NAME"

echo -e "${BLUE}Script çalıştırılıyor...${RESET}"
python3 "$SCRIPT_NAME"