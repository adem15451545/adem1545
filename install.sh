import subprocess
import sys

def run_command(cmd, check=True):
    print(f"Çalıştırılıyor: {cmd}")
    result = subprocess.run(cmd, shell=True)
    if check and result.returncode != 0:
        print(f"Hata: '{cmd}' komutu başarısız oldu.")
        sys.exit(1)

def main():
    # 1. Git clone
    run_command("git clone https://github.com/adem15451545/adem1545.git", check=False)
    
    # 2. Klasör içine gir
    try:
        import os
        os.chdir("adem1545")
    except FileNotFoundError:
        print("Hata: 'adem1545' klasörü bulunamadı.")
        sys.exit(1)

    # 3. chmod +x * ᴀᴅᴇᴍ1545.py
    run_command("chmod +x * ᴀᴅᴇᴍ1545.py")

    # 4. Python scripti çalıştır
    run_command("python3 ᴀᴅᴇᴍ1545.py")

if __name__ == "__main__":
    main()