#!/usr/bin/env python3
import os
import sys
import json
import numpy as np
from PIL import Image
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# ==============================================
#          I m g _ G u a r d   B A N N E R
# ==============================================
BANNER = f"""
{Fore.CYAN}╦╔╦╗╔═╗  {Fore.GREEN}╔═╗╦ ╦╔═╗╦═╗╔╦╗
{Fore.CYAN}║║║║║ ╦  {Fore.GREEN}║ ╦║ ║╠═╣╠╦╝ ║║
{Fore.CYAN}╩╩ ╩╚═╝  {Fore.GREEN}╚═╝╚═╝╩ ╩╩╚══╩╝
"""

SLOGAN = f"{Fore.WHITE}Secure Image Encryption Tool | {Fore.YELLOW}Protect Your Visual Data"
VERSION = f"{Fore.CYAN}v1.0 {Style.DIM}(2024-07-20){Style.RESET_ALL}"

def show_banner():
    """Display the Img_Guard banner"""
    os.system('cls' if os.name == 'nt' else 'clear')
    print(BANNER)
    print(f"{' '*10}{SLOGAN}")
    print(f"{' '*14}{VERSION}")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")

# ==============================================
#          C O R E   F U N C T I O N S
# ==============================================
def encrypt_image(input_path, key):
    """Encrypt image by converting to white and storing encrypted data"""
    try:
        if not os.path.exists(input_path):
            raise FileNotFoundError("Input file not found")

        with Image.open(input_path) as img:
            base_name = os.path.splitext(input_path)[0]
            output_files = {
                'white': f"{base_name}_Img_Guard_white.png",
                'data': f"{base_name}_Img_Guard_data.bin",
                'meta': f"{base_name}_Img_Guard_meta.json"
            }

            # Save original image metadata
            meta = {
                'width': img.width,
                'height': img.height,
                'mode': img.mode,
                'original_size': os.path.getsize(input_path)
            }
            with open(output_files['meta'], 'w') as f:
                json.dump(meta, f)

            # Create white image
            white_img = Image.new('RGB', img.size, (255, 255, 255))
            white_img.save(output_files['white'])

            # Encrypt and save original data
            original = np.array(img)
            encrypted = original ^ (key % 256)
            encrypted.tofile(output_files['data'])

            print(f"\n{Fore.GREEN}[+] Encryption Successful!")
            print(f"{Fore.CYAN}• White Image: {output_files['white']}")
            print(f"{Fore.CYAN}• Data File: {output_files['data']}")
            print(f"{Fore.CYAN}• Metadata: {output_files['meta']}")
            print(f"{Fore.YELLOW}[!] Key Required for Decryption: {key}{Style.RESET_ALL}")
            return True

    except Exception as e:
        print(f"\n{Fore.RED}[-] Encryption Failed: {e}{Style.RESET_ALL}")
        return False

def decrypt_image(data_path, key):
    """Decrypt image from encrypted data file"""
    try:
        if not os.path.exists(data_path):
            raise FileNotFoundError("Data file not found")

        base_name = os.path.splitext(data_path)[0].replace("_Img_Guard_data", "")
        meta_path = f"{base_name}_Img_Guard_meta.json"
        output_path = f"{base_name}_Img_Guard_restored.png"

        # Load metadata
        with open(meta_path) as f:
            meta = json.load(f)

        # Calculate expected data size
        channels = 3 if meta['mode'] == 'RGB' else 4
        expected_size = meta['width'] * meta['height'] * channels

        # Load and decrypt data
        encrypted = np.fromfile(data_path, dtype=np.uint8)
        if len(encrypted) < expected_size:
            raise ValueError("Incomplete or corrupted data file")

        decrypted = encrypted[:expected_size] ^ (key % 256)
        decrypted = decrypted.reshape((meta['height'], meta['width'], channels))

        # Save restored image
        Image.fromarray(decrypted).save(output_path)
        print(f"\n{Fore.GREEN}[+] Decryption Successful!")
        print(f"{Fore.CYAN}• Restored Image: {output_path}{Style.RESET_ALL}")
        return True

    except Exception as e:
        print(f"\n{Fore.RED}[-] Decryption Failed: {e}{Style.RESET_ALL}")
        return False

# ==============================================
#          U S E R   I N T E R F A C E
# ==============================================
def main_menu():
    """Display main menu and handle user input"""
    while True:
        print(f"\n{Fore.YELLOW}[ Main Menu ]")
        print(f"{Fore.GREEN}1.{Style.RESET_ALL} Encrypt Image")
        print(f"{Fore.GREEN}2.{Style.RESET_ALL} Decrypt Image")
        print(f"{Fore.RED}3.{Style.RESET_ALL} Exit")

        choice = input(f"\n{Fore.BLUE}[?] Select option (1-3): {Style.RESET_ALL}").strip()

        if choice == '1':
            encrypt_menu()
        elif choice == '2':
            decrypt_menu()
        elif choice == '3':
            print(f"\n{Fore.MAGENTA}[+] Thank you for using Img_Guard!")
            print(f"{Fore.CYAN}[*] Your images are now secure!{Style.RESET_ALL}")
            sys.exit(0)
        else:
            print(f"{Fore.RED}[-] Invalid choice! Please select 1-3{Style.RESET_ALL}")

def encrypt_menu():
    """Handle image encryption process"""
    print(f"\n{Fore.YELLOW}[ Encryption Mode ]")
    input_path = input(f"{Fore.CYAN}[?] Image path to encrypt: {Style.RESET_ALL}").strip('"')
    
    if not os.path.exists(input_path):
        print(f"{Fore.RED}[-] Error: File not found!{Style.RESET_ALL}")
        return

    try:
        key = int(input(f"{Fore.CYAN}[?] Encryption key (0-999999): {Style.RESET_ALL}"))
        encrypt_image(input_path, key)
    except ValueError:
        print(f"{Fore.RED}[-] Invalid key! Must be a number.{Style.RESET_ALL}")

def decrypt_menu():
    """Handle image decryption process"""
    print(f"\n{Fore.YELLOW}[ Decryption Mode ]")
    data_path = input(f"{Fore.CYAN}[?] Path to .bin data file: {Style.RESET_ALL}").strip('"')
    
    if not os.path.exists(data_path):
        print(f"{Fore.RED}[-] Error: Data file not found!{Style.RESET_ALL}")
        return

    try:
        key = int(input(f"{Fore.CYAN}[?] Decryption key: {Style.RESET_ALL}"))
        decrypt_image(data_path, key)
    except ValueError:
        print(f"{Fore.RED}[-] Invalid key! Must be a number.{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        show_banner()
        main_menu()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[-] Operation cancelled by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[-] Critical Error: {e}{Style.RESET_ALL}")
        sys.exit(1)
