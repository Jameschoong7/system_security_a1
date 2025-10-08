import hashlib
import os
import random
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

    print(combined_password)

