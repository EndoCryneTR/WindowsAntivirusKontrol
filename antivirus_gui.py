import tkinter as tk
from tkinter import ttk
from PIL import Image, ImageTk, ImageSequence
import threading
import os
import wmi
import pythoncom
import subprocess
import sys
import ctypes
import time
import threading
import tempfile

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )
    sys.exit()

CREATE_NO_WINDOW = 0x08000000

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
nsudo_path = os.path.join(BASE_DIR, "NSudoLC.exe")

def nsudo_run(cmd_args):
    full_cmd = [nsudo_path, "-U:T", "-ShowWindowMode:Hide"] + cmd_args
    subprocess.run(full_cmd, check=True)

class AnimatedGIF(tk.Label):
    def __init__(self, master, path, delay=100):
        super().__init__(master)
        self.delay = delay
        self.frames = []
        self.idx = 0
        self.cancel = False

        im = Image.open(path)
        try:
            resample = Image.Resampling.LANCZOS
        except AttributeError:
            resample = Image.ANTIALIAS

        for frame in ImageSequence.Iterator(im):
            frame = frame.resize((64,64), resample)
            self.frames.append(ImageTk.PhotoImage(frame))

        self.config(image=self.frames[0], bg="#000000", bd=0, highlightthickness=0)
        self.after(self.delay, self.play)

    def play(self):
        if self.cancel:
            return
        self.idx = (self.idx + 1) % len(self.frames)
        self.config(image=self.frames[self.idx])
        self.after(self.delay, self.play)

    def stop(self):
        self.cancel = True

def cozumle_durum(state):
    enabled = (state >> 0) & 0b1
    up_to_date = (state >> 1) & 0b1
    running = (state >> 4) & 0b1

    durum = []
    durum.append("Aktif" if running else "Pasif")
    durum.append("Güncel" if up_to_date else "Güncel Değil")
    durum.append("Etkinleştirilmiş" if enabled else "Devre Dışı")

    return ", ".join(durum)

komut_calisiiyor = False

def antivirus_bilgisi_al():
    global komut_calisiiyor
    if komut_calisiiyor:
        root.after(0, lambda: text_area.insert(tk.END, "⚠️ Zaten başka işlem çalışıyor. Lütfen bekleyin...\n"))
        return
    komut_calisiiyor = True
    root.after(0, lambda: text_area.delete("1.0", tk.END))

    def islem():
        pythoncom.CoInitialize()
        try:
            w = wmi.WMI(namespace="root\\SecurityCenter2")
            antivirusler = w.AntiVirusProduct()
            if not antivirusler:
                root.after(0, lambda: text_area.insert(tk.END, "🛑 Antivirüs bulunamadı.\n"))
                return

            for av in antivirusler:
                ad = av.displayName or "Bilinmiyor"
                yol = av.pathToSignedProductExe or "Yol bilgisi yok"
                durum = cozumle_durum(av.productState)
                if "kaspersky" in ad.lower():
                    durum = "Muhtemelen Aktif (Kaspersky productState verisi güvenilmez)"

                root.after(0, lambda ad=ad: text_area.insert(tk.END, f"🛡️ Antivirüs Adı: {ad}\n"))
                root.after(0, lambda yol=yol: text_area.insert(tk.END, f"📁 Yolu: {yol}\n"))
                root.after(0, lambda durum=durum: text_area.insert(tk.END, f"⚙️ Durum: {durum}\n"))
                root.after(0, lambda: text_area.insert(tk.END, "-"*50 + "\n"))

        except Exception as e:
            root.after(0, lambda: text_area.insert(tk.END, f"❌ Hata oluştu: {e}\n"))
        finally:
            pythoncom.CoUninitialize()
            global komut_calisiiyor
            komut_calisiiyor = False

    threading.Thread(target=islem, daemon=True).start()

def defender_ve_guvenlik_tam_kapali_yap():
    global text_area, komut_calisiiyor
    if komut_calisiiyor:
        root.after(0, lambda: text_area.insert(tk.END, "⚠️ Zaten bir işlem çalışıyor. Lütfen bekleyin...\n"))
        return
    komut_calisiiyor = True
    root.after(0, lambda: text_area.delete("1.0", tk.END))

    def islem():
        try:
            # 1) Virüs ve tehdit koruması kapatma
            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
                "/v", "DisableRealtimeMonitoring", "/t", "REG_DWORD", "/d", "1", "/f"
            ])
            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
                "/v", "DisableAntiSpyware", "/t", "REG_DWORD", "/d", "1", "/f"
            ])
            root.after(0, lambda: text_area.insert(tk.END, "✅ Virüs ve tehdit koruması devre dışı bırakıldı.\n"))

            # 2) Güvenlik Duvarı kapatma
            nsudo_run(["netsh", "advfirewall", "set", "allprofiles", "state", "off"])
            root.after(0, lambda: text_area.insert(tk.END, "✅ Güvenlik duvarı devre dışı bırakıldı.\n"))

            # 3) Exploit Guard kapatma
            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
                "/v", "Enabled", "/t", "REG_DWORD", "/d", "0", "/f"
            ])
            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard",
                "/v", "ExploitGuard_Enabled", "/t", "REG_DWORD", "/d", "0", "/f"
            ])
            root.after(0, lambda: text_area.insert(tk.END, "✅ Exploit Guard devre dışı bırakıldı.\n"))

            # 4) SmartScreen kapatma
            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
                "/v", "SmartScreenEnabled", "/t", "REG_SZ", "/d", "Off", "/f"
            ])
            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
                "/v", "EnableSmartScreen", "/t", "REG_DWORD", "/d", "0", "/f"
            ])
            root.after(0, lambda: text_area.insert(tk.END, "✅ SmartScreen kapatıldı.\n"))

            # 5) PUA koruması kapatma
            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
                "/v", "PUAProtection", "/t", "REG_DWORD", "/d", "0", "/f"
            ])
            root.after(0, lambda: text_area.insert(tk.END, "✅ PUA koruması kapatıldı.\n"))

            # 6) Reputation-based protection kapatma
            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender Security Center\\ReputationBasedProtection",
                "/v", "Enabled", "/t", "REG_DWORD", "/d", "0", "/f"
            ])
            root.after(0, lambda: text_area.insert(tk.END, "✅ İtibar temelli koruma kapatıldı.\n"))

            # ---- EK: Geçmiş temelli koruma alt ayarları kapatma ----
            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender Security Center\\ReputationBasedProtection",
                "/v", "SystemScanEnabled", "/t", "REG_DWORD", "/d", "0", "/f"
            ])
            root.after(0, lambda: text_area.insert(tk.END, "✅ SystemScanEnabled kapatıldı.\n"))

            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender Security Center\\ReputationBasedProtection",
                "/v", "CloudExtendedTimeoutEnabled", "/t", "REG_DWORD", "/d", "0", "/f"
            ])
            root.after(0, lambda: text_area.insert(tk.END, "✅ CloudExtendedTimeoutEnabled kapatıldı.\n"))

            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender Security Center\\ReputationBasedProtection\\Settings",
                "/v", "EnableControlledFolderAccess", "/t", "REG_DWORD", "/d", "0", "/f"
            ])
            root.after(0, lambda: text_area.insert(tk.END, "✅ Controlled Folder Access kapatıldı.\n"))

            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender Security Center\\ReputationBasedProtection\\Settings",
                "/v", "EnableNetworkProtection", "/t", "REG_DWORD", "/d", "0", "/f"
            ])
            root.after(0, lambda: text_area.insert(tk.END, "✅ Network Protection kapatıldı.\n"))

            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender Security Center\\ReputationBasedProtection\\Settings",
                "/v", "EnableExploitProtection", "/t", "REG_DWORD", "/d", "0", "/f"
            ])
            root.after(0, lambda: text_area.insert(tk.END, "✅ Exploit Protection kapatıldı.\n"))

            # 7) Defender güncelleme engeli
            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates",
                "/v", "DisableUpdateOnStartupWithoutEngine", "/t", "REG_DWORD", "/d", "1", "/f"
            ])
            root.after(0, lambda: text_area.insert(tk.END, "✅ Defender güncellemeleri engellendi.\n"))

            # 8) Servisleri durdur ve devre dışı bırak
            for svc in ["SecurityHealthService", "WinDefend", "WdNisSvc", "WdFilter"]:
                nsudo_run(["sc", "stop", svc])
                nsudo_run(["sc", "config", svc, "start= disabled"])
                root.after(0, lambda svc=svc: text_area.insert(tk.END, f"✅ Servis {svc} durduruldu ve devre dışı bırakıldı.\n"))

            # 9) Defender bildirimlerini kapatma
            nsudo_run([
                "reg", "add",
                r"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\PushNotifications",
                "/v", "ToastEnabled", "/t", "REG_DWORD", "/d", "0", "/f"
            ])
            root.after(0, lambda: text_area.insert(tk.END, "✅ Defender bildirimleri kapatıldı.\n"))

            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Notifications",
                "/v", "DisableEnhancedNotifications", "/t", "REG_DWORD", "/d", "1", "/f"
            ])
            root.after(0, lambda: text_area.insert(tk.END, "✅ Defender gelişmiş bildirimleri kapatıldı.\n"))

            root.after(0, lambda: text_area.insert(tk.END, "\n🎯 Defender, Firewall ve Uygulama Denetimi kapatıldı.\n"))

        except subprocess.CalledProcessError as e:
            root.after(0, lambda: text_area.insert(tk.END, f"❌ Hata: {e}\n"))
        finally:
            global komut_calisiiyor
            komut_calisiiyor = False

    threading.Thread(target=islem, daemon=True).start()


def defender_ve_guvenlik_tam_ac():
    global text_area, komut_calisiiyor
    if komut_calisiiyor:
        root.after(0, lambda: text_area.insert(tk.END, "⚠️ Zaten bir işlem çalışıyor. Lütfen bekleyin...\n"))
        return
    komut_calisiiyor = True
    root.after(0, lambda: text_area.delete("1.0", tk.END))

    def islem():
        try:
            # 1) Virüs ve tehdit koruması açma
            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
                "/v", "DisableRealtimeMonitoring", "/t", "REG_DWORD", "/d", "0", "/f"
            ])
            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
                "/v", "DisableAntiSpyware", "/t", "REG_DWORD", "/d", "0", "/f"
            ])
            root.after(0, lambda: text_area.insert(tk.END, "✅ Virüs ve tehdit koruması etkinleştirildi.\n"))

            # 2) Güvenlik Duvarı açma
            nsudo_run(["netsh", "advfirewall", "set", "allprofiles", "state", "on"])
            root.after(0, lambda: text_area.insert(tk.END, "✅ Güvenlik duvarı etkinleştirildi.\n"))

            # 3) Exploit Guard açma
            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
                "/v", "Enabled", "/t", "REG_DWORD", "/d", "1", "/f"
            ])
            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard",
                "/v", "ExploitGuard_Enabled", "/t", "REG_DWORD", "/d", "1", "/f"
            ])
            root.after(0, lambda: text_area.insert(tk.END, "✅ Exploit Guard etkinleştirildi.\n"))

            # 4) SmartScreen açma
            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
                "/v", "SmartScreenEnabled", "/t", "REG_SZ", "/d", "RequireAdmin", "/f"
            ])
            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
                "/v", "EnableSmartScreen", "/t", "REG_DWORD", "/d", "1", "/f"
            ])
            root.after(0, lambda: text_area.insert(tk.END, "✅ SmartScreen etkinleştirildi.\n"))

            # 5) PUA koruması açma
            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
                "/v", "PUAProtection", "/t", "REG_DWORD", "/d", "1", "/f"
            ])
            root.after(0, lambda: text_area.insert(tk.END, "✅ PUA koruması etkinleştirildi.\n"))

            # 6) Reputation-based protection açma
            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender Security Center\\ReputationBasedProtection",
                "/v", "Enabled", "/t", "REG_DWORD", "/d", "1", "/f"
            ])
            root.after(0, lambda: text_area.insert(tk.END, "✅ İtibar temelli koruma etkinleştirildi.\n"))

            # ---- EK: Geçmiş temelli koruma alt ayarları açma ----
            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender Security Center\\ReputationBasedProtection",
                "/v", "SystemScanEnabled", "/t", "REG_DWORD", "/d", "1", "/f"
            ])
            root.after(0, lambda: text_area.insert(tk.END, "✅ SystemScanEnabled açıldı.\n"))

            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender Security Center\\ReputationBasedProtection",
                "/v", "CloudExtendedTimeoutEnabled", "/t", "REG_DWORD", "/d", "1", "/f"
            ])
            root.after(0, lambda: text_area.insert(tk.END, "✅ CloudExtendedTimeoutEnabled açıldı.\n"))

            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender Security Center\\ReputationBasedProtection\\Settings",
                "/v", "EnableControlledFolderAccess", "/t", "REG_DWORD", "/d", "1", "/f"
            ])
            root.after(0, lambda: text_area.insert(tk.END, "✅ Controlled Folder Access açıldı.\n"))

            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender Security Center\\ReputationBasedProtection\\Settings",
                "/v", "EnableNetworkProtection", "/t", "REG_DWORD", "/d", "1", "/f"
            ])
            root.after(0, lambda: text_area.insert(tk.END, "✅ Network Protection açıldı.\n"))

            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender Security Center\\ReputationBasedProtection\\Settings",
                "/v", "EnableExploitProtection", "/t", "REG_DWORD", "/d", "1", "/f"
            ])
            root.after(0, lambda: text_area.insert(tk.END, "✅ Exploit Protection açıldı.\n"))

            # 7) Defender güncellemeyi açma
            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates",
                "/v", "DisableUpdateOnStartupWithoutEngine", "/t", "REG_DWORD", "/d", "0", "/f"
            ])
            root.after(0, lambda: text_area.insert(tk.END, "✅ Defender güncellemeleri açıldı.\n"))

            # 8) Servisleri başlat
            for svc in ["SecurityHealthService", "WinDefend", "WdNisSvc", "WdFilter"]:
                nsudo_run(["sc", "config", svc, "start= auto"])
                nsudo_run(["sc", "start", svc])
                root.after(0, lambda svc=svc: text_area.insert(tk.END, f"✅ Servis {svc} başlatıldı ve otomatik yapıldı.\n"))

            # Defender bildirimlerini açma
            nsudo_run([
                "reg", "add",
                r"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\PushNotifications",
                "/v", "ToastEnabled", "/t", "REG_DWORD", "/d", "1", "/f"
            ])
            root.after(0, lambda: text_area.insert(tk.END, "✅ Defender bildirimleri açıldı.\n"))

            nsudo_run([
                "reg", "add",
                r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Notifications",
                "/v", "DisableEnhancedNotifications", "/t", "REG_DWORD", "/d", "0", "/f"
            ])
            root.after(0, lambda: text_area.insert(tk.END, "✅ Defender gelişmiş bildirimleri açıldı.\n"))

            root.after(0, lambda: text_area.insert(tk.END, "\n🎯 Defender, Firewall ve Uygulama Denetimi açıldı.\n"))

        except subprocess.CalledProcessError as e:
            root.after(0, lambda: text_area.insert(tk.END, f"❌ Hata: {e}\n"))
        finally:
            global komut_calisiiyor
            komut_calisiiyor = False

    threading.Thread(target=islem, daemon=True).start()

def antivurus_test_et_thread():
    global komut_calisiiyor

    eicar_str = (
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
        "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )

    temp_dir = tempfile.gettempdir()
    test_file_path = os.path.join(temp_dir, "eicar_test_file.com")

    try:
        with open(test_file_path, "w") as f:
            f.write(eicar_str)
    except Exception as e:
        root.after(0, lambda: text_area.insert("end", f"❌ Test dosyası oluşturulamadı: {e}\n"))
        komut_calisiiyor = False
        return

    root.after(0, lambda: text_area.insert("end", f"📝 EICAR test dosyası oluşturuldu: {test_file_path}\n"))

    start_time = time.time()

    while True:
        if not os.path.exists(test_file_path):
            elapsed = time.time() - start_time
            root.after(0, lambda: text_area.insert("end", f"✅ Antivirüs {elapsed:.2f} saniyede tespit etti ve sildi.\n"))
            break

        try:
            with open(test_file_path, "rb+"):
                pass
        except PermissionError:
            elapsed = time.time() - start_time
            root.after(0, lambda: text_area.insert("end", f"✅ Antivirüs {elapsed:.2f} saniyede tespit etti ve bloke etti.\n"))
            break
        except Exception as e:
            root.after(0, lambda: text_area.insert("end", f"❌ Hata: {e}\n"))
            break

        time.sleep(0.1)

    komut_calisiiyor = False

def antivurus_test_et():
    global komut_calisiiyor
    if komut_calisiiyor:
        root.after(0, lambda: text_area.insert("end", "⚠️ Zaten başka işlem çalışıyor. Lütfen bekleyin...\n"))
        return
    komut_calisiiyor = True
    root.after(0, lambda: text_area.delete("1.0", "end"))

    threading.Thread(target=antivurus_test_et_thread, daemon=True).start()

# --- GUI Setup ---

icon_path = os.path.join(BASE_DIR, "icon.ico")
background_path = os.path.join(BASE_DIR, "background.jpg")
gif_path = os.path.join(BASE_DIR, "loading.gif")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

root = tk.Tk()
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

root.geometry(f"{screen_width}x{screen_height}+0+0")
root.iconbitmap(os.path.join(BASE_DIR, "icon.ico"))
root.title("✨ Windows Antivirüs Kontrol by EndoCryneTR")
root.minsize(600, 400)  # Minimum pencere boyutu
bg_image_orig = Image.open(os.path.join(BASE_DIR, "background.jpg"))

canvas = tk.Canvas(root, highlightthickness=0, bd=0)
canvas.pack(fill="both", expand=True)
bg_photo = None

frame = tk.Frame(canvas, bg="#000000", bd=0)
frame.place(relx=0.5, rely=0.5, anchor="center", width=600, height=500)

btn_frame = tk.Frame(frame, bg="#000000")
btn_frame.place(relx=0.5, rely=0.02, anchor="n")
btn_frame.columnconfigure([0,1,2], weight=1, uniform="a")

def resize_bg(event):
    global bg_photo
    resized = bg_image_orig.resize((event.width, event.height), Image.Resampling.LANCZOS)
    bg_photo = ImageTk.PhotoImage(resized)
    canvas.delete("bg")
    canvas.create_image(0, 0, image=bg_photo, anchor="nw", tags="bg")

canvas.bind("<Configure>", resize_bg)

# Durum metni paneli önce tanımlanmalı:
inner_frame = tk.Frame(frame, bg="#000000", bd=0)
inner_frame.place(relx=0.5, rely=0.18, anchor="n", width=580, height=450)

gif = AnimatedGIF(inner_frame, os.path.join(BASE_DIR, "loading.gif"), delay=80)
gif.pack(pady=5)

text_area = tk.Text(
    inner_frame, width=100, height=20, font=("Consolas", 10),
    bg="#000000", fg="white", insertbackground="white", bd=0, relief="flat"
)
text_area.pack(pady=10, expand=True, fill="both")

# Butonlar kısmı:

btn_check = tk.Button(
    btn_frame,
    text="Antivirüsleri Kontrol Et",
    command=antivirus_bilgisi_al,
    font=("Segoe UI", 9),
)
btn_check.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

btn_disable = tk.Button(
    btn_frame,
    text="Windows Defender'ı Kapat",
    command=defender_ve_guvenlik_tam_kapali_yap,
    font=("Segoe UI", 9),
)
btn_disable.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

btn_enable = tk.Button(
    btn_frame,
    text="Windows Defender'ı Aç",
    command=defender_ve_guvenlik_tam_ac,
    font=("Segoe UI", 9),
)
btn_enable.grid(row=0, column=2, padx=5, pady=5, sticky="ew")

btn_antivirus_test = tk.Button(
    btn_frame,
    text="Antivirüs Test Dosyası Oluştur",
    command=antivurus_test_et,
    font=("Segoe UI", 9),
)
btn_antivirus_test.grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky="ew")

root.mainloop()
