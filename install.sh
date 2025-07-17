#!/data/data/com.termux/files/usr/bin/bash

BLUE='\033[96m'
RESET='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════╗"
echo -e "║                                    ║"
echo -e "║        ᴀᴅᴇᴍ1545          ║"
echo -e "║                                    ║"
echo -e "╚════════════════════════════════════╝${RESET}"

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