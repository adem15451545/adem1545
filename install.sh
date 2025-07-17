#!/data/data/com.termux/files/usr/bin/bash

# Renk kodları (açık mavi)
BLUE='\033[96m'
RESET='\033[0m'

# Logo
echo -e "${BLUE}╔════════════════════════════════════╗"
echo -e "║                                    ║"
echo -e "║        ᴀᴅᴇᴍ1545          ║"
echo -e "║                                    ║"
echo -e "╚════════════════════════════════════╝${RESET}"

# Repo URL ve dosya ayarları
REPO_URL="https://github.com/adem15451545/adem1545.git"
DIR_NAME="adem1545"
SCRIPT_NAME="ᴀᴅᴇᴍ1545.py"

# Git yüklü değilse yükle
if ! command -v git &> /dev/null
then
    echo -e "${BLUE}Git yüklü değil, yükleniyor...${RESET}"
    pkg update -y
    pkg install git -y
fi

# Eğer klasör varsa temizle
if [ -d "$DIR_NAME" ]; then
    echo -e "${BLUE}$DIR_NAME klasörü zaten var, siliniyor...${RESET}"
    rm -rf "$DIR_NAME"
fi

# Repo klonla
echo -e "${BLUE}Repo indiriliyor...${RESET}"
git clone "$REPO_URL"

# Klasöre gir
cd "$DIR_NAME" || exit

# Çalıştırma izni ver
chmod +x "$SCRIPT_NAME"

# Scripti çalıştır
echo -e "${BLUE}Script çalıştırılıyor...${RESET}"
python3 "$SCRIPT_NAME"