# Encrypted Password Manager

## About
The Encrypted Password Manager is a command-line tool designed to securely manage and store passwords and related information. The program utilizes encryption techniques to securely save sensitive data like UserID's and Passwords.  Apart from encrypting the sensitive data, the program also implements the concept of hashing to check if the saved data has been tampered with. It provides functionalities like adding, generating, updating, viewing, finding and deleting passwords.

## Getting Started
1. Clone the repository.
2. Open the Terminal and run the following command to install the required Python modules and libraries:
```sh
    pip install -r requirements.txt
```
3. Run the program in the Terminal.

>**_NOTE:_**  Certain fetaures may not work when using Terminals built into IDEs like PyCharm. Please use the default System Terminal, Python Shell, or the VS Code Terminal (Windows Powershell).

## Project Structure
The project consists of a single Python script `encrypted_password_manager.py`, which contains all the necessary functions and logic for its implementation. The following is a brief overview of the program and its working:

### Master Password Handling:
   - The program begins by checking the integrity of the stored data, ensuring it has not been tampered with.
   - If no master password has been previously set (a FileNotFoundError will be raised and caught), it calls the `master_pwd_set()` which sets a new master password and saves it's hash to a .key file. The new master password is only set if it meets the specified conditions - verified using `regex`.
   - If the master password has been set previously, it compares the hash of the entered password to the saved one. If they match, the data file is decrypted.
   - If the passwords don't match, the user is given 2 more chances to enter the correct password after which the program will initiate a reset and delete all saved data.

### Password Operations:
   - **Find Password `find_pwd()`:** Searches for a password by its tag, decrypts and displays the information if found. Even if the entered tag doesn't exactly match (few extra letters or a typo), the `difflib` library is used to figure out the best match from the saved tags.
   - **View all Passwords `view_pwd()`:** Fetches, decrypts and displays all stored passwords in a tabulated format.
   - **Add Password `add_pwd()`:** Allows users to add new passwords with specified tags, user IDs, and either manually entered or auto-generated passwords.
   - **Generate Password `generate_pwd()`:** Automatically generates a strong password (30 characters) and offers the option to save it with a user ID. It also uses the `pyperclip` module to copy the generated password to the clipboard.
   - **Update Password `update_pwd()`:** Updates the password for a specified tag with a new manually entered or auto-generated password.
   - **Delete Password `delete_pwd()`:** Deletes the details associated with a specified tag.

### Security Measures & File Encryption:
   - The program uses the `cryptography` library for password encryption and decryption and the `hashlib` library for SHA256 hashing (For the Master Password & Checksums).
   - The passwords and related data are stored in a CSV file, encrypted with a unique key generated for each entry. Using separate keys enhances security by isolating each program run. The file is decrypted only after the successful verification of the entered master password.
   - The program ensures the integrity of these files by calculating and comparing checksums. And if any tampering in the files is detected, a program reset is initiated along with the deletion of all saved data.

## Conclusion
The Encrypted Password Manager provides a secure and user-friendly solution for managing passwords. Its design prioritizes data integrity, encryption, and user experience, ensuring a reliable and robust password management system.

## License
This project is licensed under the [MIT LICENSE](LICENSE).

## Developer
This project was created and developed by [Adithya Menon R](https://www.linkedin.com/in/adithya-menon-r).
