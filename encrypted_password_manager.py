import csv
import re
import os
import sys
import hashlib
import maskpass
import random
import pyperclip
import time

from termcolor import colored
from tabulate import tabulate
from cryptography.fernet import Fernet
from difflib import get_close_matches


def master_pwd_check():
    try:
        if not data_check():
            print(colored("DATA INTEGRITY CHECK FAILED! Data might have been tampered with.", "red", attrs=["bold"]))
            print("Initiating Program Reset...")
            time.sleep(5)
            program_reset()
            os.system('cls' if os.name == 'nt' else 'clear')
            master_pwd_set()
        else:
            pwd_error_count = 0
            while pwd_error_count < 3:
                with open("Program_Data/Master_Password.key", "r") as file:
                    master_pwd = maskpass.askpass(prompt="Enter the Master Password: ", mask="*").strip()
                    if file.read() == hash_txt_encode(master_pwd):
                        file_decrypt()
                        return True
                    else:
                        time.sleep(0.25)
                        if pwd_error_count == 0:
                            print(f"ACCESS DENIED, 2 tries left before program is reset and all data is erased.\n")
                        elif pwd_error_count == 1:
                            print(f"ACCESS DENIED, 1 try left before program is reset and all data is erased.\n")
                        pwd_error_count += 1
            if pwd_error_count == 3:
                try:
                    time.sleep(1)
                    program_reset()
                except Exception as e:
                    file_encrypt()
                    save_checksums()
                    sys.exit(colored(f"ERROR HAS OCCURRED: {e}", "red", attrs=["bold"]))
                sys.exit(colored("\nExceeded number of incorrect tries! PROGRAM HAS BEEN RESET. DATA CLEARED.", "red", attrs=["bold"]))
    except FileNotFoundError:
        master_pwd_set()


def master_pwd_set():
    print("""Master Password has not been set yet. Be sure to remember it as it cannot be reset later.
Your Master Password must have:
    • At least one uppercase letter (A-Z)
    • At least one lowercase letter (a-z)
    • At least one digit (0-9)
    • At least one special character (#?!@_$%^&*-)
    • Minimum length of 8 characters\n""")
    while True:
        master_pwd = input("Set your Master Password: ").strip()
        if re.match(r'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@_$%^&*-]).{8,100}$', master_pwd):
            master_pwd_re = maskpass.askpass(prompt="Retype the Master Password: ", mask="*").strip()
            if master_pwd == master_pwd_re:
                master_pwd_hash = hash_txt_encode(master_pwd)
                break
            else:
                print("Passwords didn't match. Please try again.\n")
        else:
            print("Invalid Password. Please follow the specified password requirements. Please try again.\n")
    os.mkdir("Program_Data")
    with open("Program_Data/Encrypted_Passwords.csv", "a", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=["Tag", "UserID", "Password", "Key"])
        writer.writeheader()
    with open("Program_Data/Master_Password.key", "w") as file:
        file.write(master_pwd_hash)
    print(colored("\nMASTER PASSWORD SET SUCCESSFULLY!\n", "green", attrs=["bold"]))
    time.sleep(0.25)


def find_pwd(tag):
    exact_match = False
    with open("Program_Data/Encrypted_Passwords.csv", "r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row["Tag"] == tag:
                exact_match = True
                time.sleep(0.25)
                print(f"\n{tag.title()} PASSWORD FOUND AND FETCHED!")
                print(f"{tag.title()} UserID: " + colored(text_decrypt(row["UserID"].encode(), row["Key"].encode()), "green", attrs=["bold"]))
                print(f"{tag.title()} Password: " + colored((text_decrypt(row["Password"].encode(), row["Key"].encode())), "green", attrs=["bold"]))
                return_confirm = input(f'\nPress {colored("Enter", "blue", attrs=["bold"])} to return to Main Menu.\n>> ').lower().strip()
                if return_confirm == "":
                    pass
    if exact_match is False:
        match = get_best_match(tag)
        if match:
            return find_pwd(match)


def view_pwd():
    data = [["Tag", "UserID", "Password"]]
    with open("Program_Data/Encrypted_Passwords.csv", "r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            data.append([row["Tag"].title(), text_decrypt(row["UserID"].encode(), row["Key"].encode()),
                         text_decrypt(row["Password"].encode(), row["Key"].encode())])
    os.system('cls' if os.name == 'nt' else 'clear')
    time.sleep(0.25)
    print(colored("PASSWORDS FETCHED SUCCESSFULLY!", "green", attrs=["bold"]))
    print(tabulate(data, headers="firstrow", tablefmt="heavy_grid"))
    return_confirm = input(f'Press {colored("Enter", "blue", attrs=["bold"])} to return to Main Menu.\n>> ').lower().strip()
    if return_confirm == "":
        pass


def add_pwd(tag, user_id, pwd):
    with open("Program_Data/Encrypted_Passwords.csv", "a", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=["Tag", "UserID", "Password", "Key"])
        key = Fernet.generate_key()
        writer.writerow({"Tag": tag.lower(), "UserID": text_encrypt(user_id.encode(), key).decode(), "Password": text_encrypt(pwd.encode(), key).decode(), "Key": key.decode()})
    print(colored(f"\n{tag} Password Saved!", "green", attrs=["bold"]))
    time.sleep(0.5)


def generate_pwd(copy=False):
    gen_pwd = ""
    characters = "0123456789@ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz#?!@_$%^&*-"
    while True:
        for i in range(30):
            gen_pwd += random.choice(characters)
        if re.match(r'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^_&*-]).{8,}$', gen_pwd):
            if copy:
                pyperclip.copy(gen_pwd)
            return gen_pwd
        else:
            gen_pwd = ""


def update_pwd(tag):
    data = []
    exact_match = False
    pwd_update = False
    with open("Program_Data/Encrypted_Passwords.csv", "r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            data.append(row)
    for i in range(len(data)):
        if data[i]["Tag"] == tag:
            exact_match = True
            gen_confirm = input(f"Do you want update {tag.title()}'s password with a secure auto generated one (Yes/No)? ").lower().strip()
            if gen_confirm in ["yes", "y"]:
                new_pwd = generate_pwd()
            else:
                new_pwd = input(f"Enter the new password for {tag.title()}: ").strip()
            print(f"\nNew Password for {tag.title()} = {colored(new_pwd, 'blue', attrs=['bold'])}")
            confirm = input("Proceed with saving data (Yes/No)? -> ").lower().strip()
            if confirm in ["y", "yes"]:
                pwd_update = True
                data[i]["Password"] = text_encrypt(new_pwd.encode(), data[i]["Key"].encode()).decode()
            break

    if exact_match is True:
        with open("Program_Data/Encrypted_Passwords.csv", "w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=["Tag", "UserID", "Password", "Key"])
            writer.writeheader()
            for pwd_set in data:
                writer.writerow(pwd_set)
        if pwd_update:
            print(colored(f"\n{tag.title()}'s password was UPDATED successfully!", "green", attrs=["bold"]))
            time.sleep(0.5)
    elif exact_match is False:
        match = get_best_match(tag)
        if match:
            return update_pwd(match)


def delete_pwd(tag):
    data = []
    exact_match = False
    with open("Program_Data/Encrypted_Passwords.csv", "r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            data.append(row)
    for i in range(len(data)):
        if data[i]["Tag"] == tag:
            exact_match = True
            confirm_delete = input(f"Are you sure you want to DELETE {tag}'s details (Yes/No)? ").lower().strip()
            if confirm_delete in ["yes", "y"]:
                data.pop(i)
                break
            else:
                return None
            
    if exact_match is True:
        with open("Program_Data/Encrypted_Passwords.csv", "w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=["Tag", "UserID", "Password", "Key"])
            writer.writeheader()
            for pwd_set in data:
                writer.writerow(pwd_set)
        print(colored(f"\n{tag.title()}'s details were DELETED successfully!", "green", attrs=["bold"]))
        time.sleep(0.5)
    elif exact_match is False:
        match = get_best_match(tag)
        if match:
            return delete_pwd(match)


def get_best_match(tag):
    pwd_tags = []
    with open("Program_Data/Encrypted_Passwords.csv", "r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            pwd_tags.append(row["Tag"])
    matches = get_close_matches(tag.lower(), pwd_tags)
    if matches:
        print(colored("TAG NOT FOUND!", "red", attrs=["bold"]))
        time.sleep(0.25)
        tag_confirm = input(f"\nDid you mean \"{matches[0]}\" (Yes/No)? ").lower().strip()
        if tag_confirm in ["y", "yes"]:
            return matches[0]
        else:
            retry_confirm = input(f'Press {colored("R", "blue", attrs=["bold"])} to retry or Press {colored("Enter", "blue", attrs=["bold"])} to go back to Main Menu: ').lower().strip()
            if retry_confirm in ["r", "retry"]:
                tag = input("\nEnter the Password/App Tag: ").strip()
                return tag
            return None
    else:
        print(colored("TAG NOT FOUND!", "red", attrs=["bold"]))
        retry_confirm = input(f'Press {colored("R", "blue", attrs=["bold"])} to retry or Press {colored("Enter", "blue", attrs=["bold"])} to go back to Main Menu: ').lower().strip()
        if retry_confirm in ["r", "retry"]:
            tag = input("\nEnter the Password/App Tag: ").strip()
            return tag
        return None


def hash_txt_encode(txt):
    hash = hashlib.sha256(txt.encode())
    hex_hash = hash.hexdigest()
    return hex_hash


def data_check():
    data_intact = True
    with open("Program_Data/Checksums.csv", "r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row["Checksum"].strip():
                stored_checksum = row["Checksum"].strip()
            else:
                stored_checksum = None
            if stored_checksum is not None and file_tamper_check(stored_checksum, row["File Path"]):
                data_intact = False
                break
    if data_intact:
        return True
    else:
        return False


def file_tamper_check(stored_checksum, path):
    current_checksum = calculate_checksum(path)
    return current_checksum != stored_checksum


def calculate_checksum(path):
    hash = hashlib.sha256()
    with open(path, "rb") as file:
        while checksum_data := file.read(8192):
            hash.update(checksum_data)
    return hash.hexdigest()


def save_checksums():
    with open("Program_Data/Checksums.csv", "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=["File Path", "Checksum"])
        writer.writeheader()
        writer.writerow({"File Path": "Program_Data/Encrypted_Passwords.csv", "Checksum": calculate_checksum("Program_Data/Encrypted_Passwords.csv")})
        writer.writerow({"File Path": "Program_Data/Master_Password.key", "Checksum": calculate_checksum("Program_Data/Master_Password.key")})
        writer.writerow({"File Path": "Program_Data/File_Encryption_Key.key", "Checksum": calculate_checksum("Program_Data/File_Encryption_Key.key")})


def text_encrypt(txt: bytes, key: bytes):
    fernet = Fernet(key)
    encrypted_text = fernet.encrypt(txt)
    return encrypted_text


def text_decrypt(txt: bytes, key: bytes):
    fernet = Fernet(key)
    decrypted_text = fernet.decrypt(txt).decode()
    return decrypted_text


def file_encrypt():
    key = Fernet.generate_key()
    with open("Program_Data/Encrypted_Passwords.csv", "rb") as file_data:
        data = file_data.read()
    with open("Program_Data/File_Encryption_Key.key", "wb") as file_key:
        file_key.write(key)
    with open("Program_Data/Encrypted_Passwords.csv", "wb") as file:
        file.write(text_encrypt(data, key))


def file_decrypt():
    with open("Program_Data/File_Encryption_Key.key", "rb") as file_key:
        key = file_key.read()
    with open("Program_Data/Encrypted_Passwords.csv", "rb") as file_data:
        data = file_data.read()
    with open("Program_Data/Encrypted_Passwords.csv", "wb") as file:
        file.write(text_decrypt(data, key).encode())


def passwords_exist():
    pwd_tags = []
    with open("Program_Data/Encrypted_Passwords.csv", "r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            pwd_tags.append(row["Tag"])
    if len(pwd_tags) >= 1:
        return True
    else:
        print(colored("\nOperation can't be performed as NO PASSWORDS HAVE BEEN SAVED!", "red", attrs=["bold"]))
        time.sleep(0.5)
        return False


def tag_exists(tag):
    pwd_tags = []
    with open("Program_Data/Encrypted_Passwords.csv", "r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            pwd_tags.append(row["Tag"].upper())
    if tag.upper() in pwd_tags:
        return True
    else:
        return False


def delete_item(path, directory=False):
    try:
        if directory:
            os.rmdir(path)
        else:
            os.remove(path)
    except FileNotFoundError:
        pass


def program_reset():
    delete_item("Program_Data/Encrypted_Passwords.csv")
    delete_item("Program_Data/Master_Password.key")
    delete_item("Program_Data/File_Encryption_Key.key")
    delete_item("Program_Data/Checksums.csv")
    delete_item("Program_Data", True)


def main():
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("-------------------------------------------------------------------------------------------")
        print("ENCRYPTED PASSWORD MANAGER")
        print("-------------------------------------------------------------------------------------------")

        if master_pwd_check() is True:
            print(colored("\nACCESS GRANTED...", "green", attrs=["bold"]), end="")
            time.sleep(0.25)

        operations = [
            [1, "Find Password"],
            [2, "View all Passwords"],
            [3, "Add Password"],
            [4, "Generate Password"],
            [5, "Update Password"],
            [6, "Delete Password"]
        ]

        while True:
            time.sleep(1)
            os.system('cls' if os.name == 'nt' else 'clear')
            print("\nCHOOSE THE DESIRED OPERATION (1/2/3/4/5/6)")
            operation_choice = input(tabulate(operations, tablefmt="rounded_grid") + f"\nPress {colored('Q', 'blue', attrs=['bold'])} to quit the program.\n>> ").lower().strip()
            
            if operation_choice in ["1", "find", "find password"]:
                if passwords_exist():
                    tag = input("\nEnter the Password/App Tag to search for: ").strip().lower()
                    find_pwd(tag)

            elif operation_choice in ["2", "view", "view all passwords"]:
                if passwords_exist():
                    time.sleep(0.25)
                    view_pwd()

            elif operation_choice in ["3", "add", "add password"]:
                while True:
                    pwd_tag = input("\nPassword/App Tag: ").strip()
                    while True:
                        if tag_exists(pwd_tag):
                            print("ERROR! Password Tag already exists!")
                            pwd_tag = input("\nChoose a new Password/App Tag: ").strip()
                        else:
                            break
                    user_id = input(f"{pwd_tag} User ID: ").strip()
                    gen_confirm = input(f"Do you want to auto generate a password for {pwd_tag} (Yes/No)? ").lower().strip()
                    if gen_confirm in ["yes", "y"]:
                        pwd = generate_pwd()
                    else:
                        pwd = input(f"{pwd_tag} Password: ").strip()
                    print(f"\n{pwd_tag} User ID = {colored(user_id, 'blue', attrs=['bold'])}\n{pwd_tag} Password = {colored(pwd, 'blue', attrs=['bold'])}")
                    confirm = input("Proceed with saving data (Yes/No)? -> ").lower().strip()
                    if confirm in ["y", "yes"]:
                        add_pwd(pwd_tag, user_id, pwd)
                        break
                    else:
                        retry_confirm = input(f'\nPress {colored("R", "blue", attrs=["bold"])} to retry or Press {colored("Enter", "blue", attrs=["bold"])} to go back to Main Menu: ').lower().strip()
                        if retry_confirm not in ["r", "retry"]:
                            break

            elif operation_choice in ["4", "generate", "generate password"]:
                gen_pwd = generate_pwd(copy=True)
                time.sleep(0.5)
                print("\nPassword Generated and Copied to Clipboard")
                print("Generated Password is:", colored(gen_pwd, "green", attrs=["bold"]))
                save_confirm = input("\nDo you want to save this password (Yes/No)? ").lower().strip()
                if save_confirm in ["yes", "y"]:
                    pwd_tag = input("\nPassword/App Tag: ").strip()
                    while True:
                        if tag_exists(pwd_tag):
                            print("ERROR! Password Tag already exists!")
                            pwd_tag = input("\nChoose a new Password/App Tag: ").strip()
                        else:
                            break
                    user_id = input(f"{pwd_tag} User ID: ").strip()
                    print(f"\n{pwd_tag} User ID = {colored(user_id, 'blue', attrs=['bold'])}\n{pwd_tag} Password = {colored(gen_pwd, 'blue', attrs=['bold'])}")
                    confirm = input("Proceed with saving data (Yes/No)? -> ").lower().strip()
                    if confirm in ["y", "yes"]:
                        add_pwd(pwd_tag, user_id, gen_pwd)

            elif operation_choice in ["5", "update", "update password"]:
                if passwords_exist():
                    tag = input("\nEnter the Password/App Tag to update: ").strip().lower()
                    update_pwd(tag)

            elif operation_choice in ["6", "delete", "del", "delete password"]:
                if passwords_exist():
                    tag = input("\nEnter the Password/App Tag to delete: ").strip().lower()
                    delete_pwd(tag)

            elif operation_choice in ["q", "quit"]:
                time.sleep(0.5)
                print(colored("\nPROGRAM HAS QUIT SUCCESSFULLY!\n", "red", attrs=["bold"]))
                file_encrypt()
                save_checksums()
                break
            
            else:
                print("Invalid Operation. Please try again")
                time.sleep(0.5)

    except KeyboardInterrupt:
        try:
            file_encrypt()
            save_checksums()
        except FileNotFoundError:
            pass
        sys.exit(colored('\n\nPROGRAM WAS FORCE QUIT DUE TO "KeyBoardInterrupt"!\n', "red", attrs=["bold"]))


if __name__ == "__main__":
    main()
