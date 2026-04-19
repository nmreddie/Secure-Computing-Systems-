import hashlib
import os
import time
import re
import json

CREDENTIAL_FILE = "user_records.json"

# Load existing user records from storage
def fetch_users():
    if os.path.exists(CREDENTIAL_FILE):
        with open(CREDENTIAL_FILE, "r") as f:
            return json.load(f)
    return {}

# Persist user records to storage
def store_users(user_data):
    with open(CREDENTIAL_FILE, "w") as f:
        json.dump(user_data, f, indent=4)

# Create a random salt for password protection
def create_salt():
    return os.urandom(16).hex()

# Produce SHA-256 hash from password and salt
def encrypt_password(pwd, salt):
    return hashlib.sha256((pwd + salt).encode()).hexdigest()

# Check that password meets strength requirements
def check_password_strength(pwd):
    issues = []

    if len(pwd) < 12:
        issues.append("At least 12 characters are required")
    if not re.search(r"[A-Z]", pwd):
        issues.append("An uppercase letter is required")
    if not re.search(r"[a-z]", pwd):
        issues.append("A lowercase letter is required")
    if not re.search(r"\d", pwd):
        issues.append("A numeric digit is required")
    if not re.search(r"[!@#$%^&*]", pwd):
        issues.append("A special character (!@#$%^&*) is required")

    if issues:
        print("\nPassword does not meet the following criteria:")
        for issue in issues:
            print(" -", issue)
        return False

    print("Password strength verified successfully")
    return True

# Handle new user registration
def create_account(user_data):
    print("\n--- NEW USER REGISTRATION ---")
    uname = input("Choose a username: ").strip()

    if uname in user_data:
        print("This username is already taken")
        return

    pwd = input("Set a password: ")

    if not check_password_strength(pwd):
        return

    salt = create_salt()
    user_data[uname] = {
        "password_hash": encrypt_password(pwd, salt),
        "salt_value": salt,
        "failed_count": 0,
        "is_locked": False
    }

    store_users(user_data)
    print("Account created successfully!")

# Handle user login with brute-force protection
def authenticate_user(user_data):
    print("\n--- USER LOGIN ---")
    uname = input("Enter your username: ").strip()

    if uname not in user_data:
        print("No account found with that username")
        return

    account = user_data[uname]

    if account["is_locked"]:
        print("This account has been locked due to too many failed attempts")
        return

    pwd = input("Enter your password: ")
    pwd_hash = encrypt_password(pwd, account["salt_value"])

    if pwd_hash == account["password_hash"]:
        print("Access granted. Welcome!")
        account["failed_count"] = 0
    else:
        print("Incorrect password. Access denied")
        account["failed_count"] += 1
        time.sleep(2)

        if account["failed_count"] >= 3:
            account["is_locked"] = True
            print("Account locked after 3 consecutive failed attempts")

    store_users(user_data)

# Display all registered usernames
def list_accounts(user_data):
    print("\n--- REGISTERED ACCOUNTS ---")
    if not user_data:
        print("No users registered yet")
        return
    for uname in user_data:
        print(" •", uname)

# Display the main navigation menu
def display_menu():
    print("\n========================================")
    print("       SECURE AUTHENTICATION SYSTEM     ")
    print("========================================")
    print("  1. Create New Account")
    print("  2. Login")
    print("  3. View All Accounts")
    print("  4. Exit")
    print("========================================")

# Entry point — runs the main application loop
def main():
    user_data = fetch_users()

    while True:
        display_menu()
        option = input("Enter your choice (1-4): ").strip()

        if option == "1":
            create_account(user_data)
        elif option == "2":
            authenticate_user(user_data)
        elif option == "3":
            list_accounts(user_data)
        elif option == "4":
            print("Goodbye! Exiting the system.")
            break
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()