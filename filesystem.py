import hashlib
import os
import random
import json
import string
import sys

#File Paths
SALT_FILE = "salt.txt"
SHADOW_FILE = "shadow.txt"
FILES_STORE = "Files.store"


#Function to display md5 test output on startup
def test_md5():
    test_value = "This is a test"
    h = hashlib.new("md5")
    h.update(test_value.encode())
    print(f"MD5('{test_value}') = {h.hexdigest()}")

#Function to generate random salt
def generate_salt():
    #Random 8 digit string
    digits = string.digits
    salt = ''.join(random.choices(digits,k=8))
    return salt

#Function to hash password with salt
def hash_password(password, salt):
    combined_password = f"{password}{salt}"
    h = hashlib.new("md5")
    h.update(combined_password.encode())
    return h.hexdigest()


#Function to load data from file
def load_data():
    users={}
    files ={}
    
    # Load salts from salt.txt
    try:
        with open(SALT_FILE,'r') as f:
            for line in f:
                username, salt = line.strip().split(':')
    except FileNotFoundError:
        print("salt.txt not found.")

    # load hashes and clearances from shadow.txt
    try:
        with open(SHADOW_FILE, 'r') as f:
            for line in f:
                username, hash_val, clearance = line.strip().split(':')
                if username in users:
                    # Add hash and clearance to the existing user dictionary
                    users[username]['hash'] = hash_val
                    users[username]['clearance'] = int(clearance)
    except FileNotFoundError:
        print("shadow.txt not found")

    #load file from Files.store
    try:
        with open(FILES_STORE,'r') as f:
            # json is used to parse the file directly into the dictionary
            files = json.load(f)
    except FileNotFoundError:
        print("Files.store not found")

    return users,files

#Function to save user data to file
def save_data(users, files):
     # 1. Save salts to salt.txt, overwriting the old file
    with open(SALT_FILE, 'w') as f:
        for username, data in users.items():
            f.write(f"{username}:{data['salt']}\n")

    # 2. Save hashes and clearances to shadow.txt
    with open(SHADOW_FILE, 'w') as f:
        for username, data in users.items():
            f.write(f"{username}:{data['hash']}:{data['clearance']}\n")

    # 3. Save the file system simulation to Files.store
    with open(FILES_STORE, 'w') as f:
        # Use json.dump with indent=4 for human-readable output
        json.dump(files, f, indent=4)
    print("Data successfully saved.")

#Function to validate password
def validate_password(password):
    if len(password)<=6:
        print("Password should more than 6 letter")
        return False
    has_digit = False
    has_alphabet = False    
    for char in password:
        if char.isdigit():
            has_digit = True
        if char.isalpha():
            has_alphabet = True
    if has_digit and has_alphabet:
        return True
    return False

#Function to register user (FileSystem -i)
def register_user(users):
    #Check if username exist
    username = input("Username: ")
    if username in users:
        raise Exception("The username exists already. Program will terminate.")
    
    #Ask for password
    while True:
    
        password = input("Password:")
        if(validate_password(password)):
            confirm_password =  input("Comfirm password: ")
            if password == confirm_password:
                break  # Exit loop on success
            else:
                print("Passwords do not match. Please try again.\n")
    
    #Get clearance level
    clearance = -1
    while clearance not in [0, 1, 2, 3]:
        try:
            clearance = int(input("User clearance (0, 1, 2, or 3): "))
            if clearance not in [0, 1, 2, 3]:
                print("Invalid clearance level. Please choose 0, 1, 2, or 3.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    salt = generate_salt()
    pass_salt_hash = hash_password(password,salt)

    users[username]={'salt':salt,'hash':pass_salt_hash,'clearance': clearance}
    print(f"User {username} created successfully")
        
users = {"test1":1}
register_user(users)

