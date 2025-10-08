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

test_md5()