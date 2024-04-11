# Encrypted Password Manager

## Overview
The Encrypted Password Manager is a command-line tool designed to securely manage and store passwords and related information. The program utilizes encryption techniques to securely save sensitive data like UserID's and Passwords.  Apart from encrypting the sensitive data, the program also implements the concept of hashing to check if the saved data has been tampered with. It provides functionalities like adding, generating, updating, viewing, finding and deleting passwords.


## Getting Started
1. Download the Source Code or clone this Repository using:
```sh
      git clone https://github.com/adithya-menon-r/Encrypted-Password-Manager.git
```
2. Run the following command to install the required modules and libraries:
```sh
      pip install -r requirements.txt
```

## Project Structure
The project consists of a single Python script "project.py", which contains all the necessary functions and logic for its implementation. The following is a brief overview of the program and its working:

1. **Master Password Handling:**
   - The program begins by checking the integrity of the stored data, ensuring it has not been tampered with.
   - If no master password is set (FileNotFoundError will be raised and caught), it calls the `master_pwd_set()` which sets a new master password and saves it's hash to the data. The master password entered by the user is accepted only if it meets the specified conditions - verified using `regex`.
   - If the master password has been set previously, it continues within the `master_pwd_check()` function and checks if the entered password's hash matches with the one saved.
   - If the passwords don't match, the user is given 2 more chances to enter the correct password after which the program will initiate a reset and delete all saved data.

2. **Password Operations:**
   - **Find Password `find_pwd()`:** Searches for a password by its tag, decrypts and displays the information if found. The password can be searched by:
        - Specifiying the exact tag
        - Inputting the first few letters of the tag - Uses `difflib` library to figure out the best match from the saved tags to produce the desired result.
   - **View all Passwords `view_pwd()`:** Fetches and displays all stored passwords in a tabulated format.
   - **Add Password `add_pwd()`:** Allows users to add new passwords with specified tags, user IDs, and either manually entered or auto-generated passwords.
   - **Generate Password `generate_pwd()`:** Automatically generates a strong password, and offers an option to save it with a user ID.
   - **Update Password `update_pwd()`:** Updates the password for a specified tag with a new manually entered or auto-generated password.
   - **Delete Password `delete_pwd()`:** Deletes the details associated with a specified tag.

3. **Security Measures & File Encryption:**
   - The program uses the `cryptography` library for password encryption and decryption and the `hashlib` library for SHA256 hashing.
   - The passwords are stored in a CSV file (`Encrypted_Passwords.csv`), which is encrypted using a key stored in `File_Encryption_Key.key`.
   - The program ensures the integrity of these files by calculating and comparing checksums. And if any tampering in the files are detected, a program reset is initiated along with the deletion of all saved data.

## Design Choices
- **Password Management:**
    - Passwords are stored in a CSV file, encrypted with a unique key generated for each entry. Using separate keys enhances security by isolating each password entry.
    - A CSV file provides an easily integratable and lightweight format for storing structured password data, facilitating compatibility and quick prototyping. Additionally, it aligns with the projct's focus on simplicity.

- **User Interaction:**
  - Clear and concise prompts guide users through operations, with error handling for invalid inputs.
  - The program also makes use of the `termcolor` module to print text, improving readability and providing visual cues for status messages, errors, and successful operations. This contributes to a more user-friendly and informative command-line interface.

- **Program Reset:**
  - In the event of incorrect master password attempts or data tampering, the program performs a reset, clearing all data.
  - This proactive measure prevents unauthorized access or compromise of stored passwords, and maintains the security of sensitive information.

## Conclusion
The Encrypted Password Manager provides a secure and user-friendly solution for managing passwords. Its design prioritizes data integrity, encryption, and user experience, ensuring a reliable and robust password management system.

<hr>

This project was created and developed by [Adithya Menon R.](https://www.linkedin.com/in/adithya-menon-r)
