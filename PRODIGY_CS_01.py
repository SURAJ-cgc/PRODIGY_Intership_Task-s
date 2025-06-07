import base64
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def display_banner():
    """Display colorful program banner"""
    print(f"\n{Fore.RED}   _____ _       _                {Fore.GREEN} _____  ___  {Fore.BLUE} ____  ")
    print(f"{Fore.RED}  / ____(_)     | |              {Fore.GREEN}|___  |/ _ \\ {Fore.BLUE}|___ \\ ")
    print(f"{Fore.RED} | |     _ _ __ | |__   ___ _ __ {Fore.GREEN}   / /| | | |{Fore.BLUE}  __) |")
    print(f"{Fore.RED} | |    | | '_ \\| '_ \\ / _ \\ '__|{Fore.GREEN} / / | | | |{Fore.BLUE} |__ < ")
    print(f"{Fore.RED} | |____| | |_) | | | |  __/ |   {Fore.GREEN}/ /__| |_| |{Fore.BLUE} ___) |")
    print(f"{Fore.RED}  \\_____|_| .__/|_| |_|\\___|_|   {Fore.GREEN}\\_____/\\___/ {Fore.BLUE}|____/ ")
    print(f"{Fore.RED}          | |                     {Fore.YELLOW}{Style.BRIGHT}Cipher64 Pro")
    print(f"{Fore.RED}          |_|    {Fore.CYAN}Enhanced Caesar Cipher Program with Base64 Tools{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}{'='*65}{Style.RESET_ALL}\n")

def caesar_cipher(text, shift, mode):
    """Encrypts/decrypts text using Caesar Cipher algorithm."""
    result = ""
    if mode == 'decrypt':
        shift = -shift
    
    for char in text:
        if char.isupper():
            result += chr((ord(char) + shift - 65) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) + shift - 97) % 26 + 97)
        else:
            result += char
    return result

def base64_decode_wrapper():
    """Handles Base64 decoding with error handling"""
    print(f"\n{Fore.BLUE}Base64 Decoder")
    print(f"{Fore.BLUE}{'-'*14}{Style.RESET_ALL}")
    while True:
        message = input(f"\n{Fore.YELLOW}Enter Base64 encoded message (or 'back' to return): {Style.RESET_ALL}")
        if message.lower() == 'back':
            return
        
        try:
            decoded_bytes = base64.b64decode(message.encode('ascii'))
            decoded_text = decoded_bytes.decode('ascii')
            print(f"\n{Fore.GREEN}Decoded message: {Fore.WHITE}{decoded_text}{Style.RESET_ALL}")
            
            if decoded_text.isprintable() and any(c.isalpha() for c in decoded_text):
                cipher_choice = input(f"\n{Fore.YELLOW}Does this look like a Caesar cipher message? (y/n): {Style.RESET_ALL}").lower()
                if cipher_choice == 'y':
                    shift = int(input(f"{Fore.YELLOW}Enter the shift value for decryption (1-25): {Style.RESET_ALL}"))
                    decrypted = caesar_cipher(decoded_text, shift, 'decrypt')
                    print(f"\n{Fore.GREEN}Final decrypted message: {Fore.WHITE}{decrypted}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error decoding Base64: {str(e)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Please enter a valid Base64 encoded message.{Style.RESET_ALL}")

def main():
    display_banner()
    
    while True:
        print(f"\n{Fore.CYAN}Main Menu:{Style.RESET_ALL}")
        print(f"{Fore.GREEN}1. {Fore.WHITE}Encrypt a message (Caesar Cipher){Style.RESET_ALL}")
        print(f"{Fore.GREEN}2. {Fore.WHITE}Decrypt a message (Caesar Cipher){Style.RESET_ALL}")
        print(f"{Fore.GREEN}3. {Fore.WHITE}Base64 Decoder{Style.RESET_ALL}")
        print(f"{Fore.GREEN}4. {Fore.WHITE}Exit{Style.RESET_ALL}")
        
        choice = input(f"\n{Fore.YELLOW}Enter your choice (1-4): {Style.RESET_ALL}")
        
        if choice == '1':
            message = input(f"\n{Fore.YELLOW}Enter the message to encrypt: {Style.RESET_ALL}")
            shift = int(input(f"{Fore.YELLOW}Enter the shift value (1-25): {Style.RESET_ALL}"))
            encrypted = caesar_cipher(message, shift, 'encrypt')
            print(f"\n{Fore.GREEN}Caesar Encrypted message: {Fore.WHITE}{encrypted}{Style.RESET_ALL}")
            
            base64_choice = input(f"\n{Fore.YELLOW}Would you like additional Base64 encoding? (y/n): {Style.RESET_ALL}").lower()
            if base64_choice == 'y':
                base64_encrypted = base64.b64encode(encrypted.encode('ascii')).decode('ascii')
                print(f"\n{Fore.GREEN}Base64 Encoded message: {Fore.WHITE}{base64_encrypted}{Style.RESET_ALL}")
        
        elif choice == '2':
            message = input(f"\n{Fore.YELLOW}Enter the message to decrypt: {Style.RESET_ALL}")
            
            if (len(message) % 4 == 0 and 
                all(c.isalnum() or c in {'+', '/', '='} for c in message)):
                base64_choice = input(f"{Fore.YELLOW}This looks like Base64. Decode it first? (y/n): {Style.RESET_ALL}").lower()
                if base64_choice == 'y':
                    try:
                        message = base64.b64decode(message.encode('ascii')).decode('ascii')
                        print(f"\n{Fore.GREEN}Base64 decoded message: {Fore.WHITE}{message}{Style.RESET_ALL}")
                    except:
                        print(f"{Fore.RED}Invalid Base64 - proceeding with normal decryption{Style.RESET_ALL}")
            
            shift = int(input(f"{Fore.YELLOW}Enter the shift value (1-25): {Style.RESET_ALL}"))
            decrypted = caesar_cipher(message, shift, 'decrypt')
            print(f"\n{Fore.GREEN}Decrypted message: {Fore.WHITE}{decrypted}{Style.RESET_ALL}")
        
        elif choice == '3':
            base64_decode_wrapper()
        
        elif choice == '4':
            print(f"\n{Fore.MAGENTA}Exiting the program. Goodbye!{Style.RESET_ALL}")
            break
            
        else:
            print(f"\n{Fore.RED}Invalid choice. Please enter a number between 1-4.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
