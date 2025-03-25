import bcrypt
import secrets
import string
import os
import json
import base64
import time

data_file = 'password_manager_data.json'
failed_attempts = {}
MAX_ATTEMPTS = 3
TIMEOUT_DURATION = 30

def generate_password(length=12):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return base64.b64encode(hashed_password).decode('utf-8')

def verify_password(stored_hash, password_to_verify):
    decoded_hash = base64.b64decode(stored_hash.encode('utf-8'))
    return bcrypt.checkpw(password_to_verify.encode('utf-8'), decoded_hash)

def save_password_data(account_name, password_hash, key):
    data = {}
    if os.path.exists(data_file) and os.path.getsize(data_file) > 0:
        with open(data_file, 'r') as file:
            try:
                data = json.load(file)
            except json.JSONDecodeError:
                print("Error reading the file. It might be corrupted.")
                return False

    data[account_name] = {
        'key': key,
        'hash': password_hash
    }

    with open(data_file, 'w') as file:
        json.dump(data, file, indent=4)

    return True

def retrieve_password(account_name, entered_password):
    data = {}
    if os.path.exists(data_file) and os.path.getsize(data_file) > 0:
        with open(data_file, 'r') as file:
            try:
                data = json.load(file)
            except json.JSONDecodeError:
                print("Error reading the file. It might be corrupted.")
                return False

        if account_name in data:
            stored_hash = data[account_name]['hash']
            if verify_password(stored_hash, entered_password):
                return data[account_name]['key']
            else:
                return False
    return False


def retrieve_account(account_name, entered_key):
    data = {}
    if os.path.exists(data_file) and os.path.getsize(data_file) > 0:
        with open(data_file, 'r') as file:
            try:
                data = json.load(file)
            except json.JSONDecodeError:
                print("Error reading the file. It might be corrupted.")
                return False

        if account_name in data:
            stored_key = data[account_name]['key']
            if stored_key == entered_key:
                print(f"Key is correct for '{account_name}'.")

                new_password = generate_password()
                new_hashed_password = hash_password(new_password)
                new_key = secrets.token_hex(16)

                data[account_name]['hash'] = new_hashed_password
                data[account_name]['key'] = new_key

                with open(data_file, 'w') as file:
                    json.dump(data, file, indent=4)

                print(f"Your account has been successfully reset.")
                print(f"New password: {new_password}")
                print(f"New key: {new_key}")
                return True
            else:
                print("The entered key is incorrect.")
                return False
    else:
        print("No data file exists.")
        return False

if __name__ == "__main__":
    while True:
        print("1. Create a new account and generate a password")
        print("2. Verify password for an account")
        print("3. Reset your account using a key")
        print("4. Exit")

        choice = input("Choose an option: ")

        if choice == '1':
            account_name = input("Enter the account name: ")
            password = generate_password()
            key = secrets.token_hex(16)
            hashed_password = hash_password(password)
            result = save_password_data(account_name, hashed_password, key)
            if result:
                print(f"Password for '{account_name}' generated and saved. Password: {password}")
                print(f"Key for '{account_name}': {key}")
            else:
                print("Error saving the password.")


        elif choice == '2':
            if 'failed_attempts' not in globals():
                failed_attempts = {}
            account_name = input("Enter the account name: ")
            entered_password = input("Enter your password to verify: ")
            if account_name in failed_attempts:
                attempts, lockout_time = failed_attempts[account_name]
                if attempts >= MAX_ATTEMPTS:
                    if time.time() - lockout_time < TIMEOUT_DURATION:
                        remaining_time = TIMEOUT_DURATION - (time.time() - lockout_time)
                        print(f"Time-out active. Try again in {int(remaining_time)} seconds.")

                    else:
                        del failed_attempts[account_name]

            result = retrieve_password(account_name, entered_password)

            if result:
                print("Password correct!")
                if account_name in failed_attempts:
                    del failed_attempts[account_name]
            else:
                print("Wrong password.")

                if account_name not in failed_attempts:
                    failed_attempts[account_name] = [0, time.time()]

                failed_attempts[account_name][0] += 1
                failed_attempts[account_name][1] = time.time()

                if failed_attempts[account_name][0] >= MAX_ATTEMPTS:
                    print(f"Too many failed attempts. Time-out of {TIMEOUT_DURATION} seconds activated.")

        elif choice == '3':
            account_name = input("Enter the account name to retrieve: ")
            entered_key = input("Enter the key for this account: ")
            retrieve_account(account_name, entered_key)

        elif choice == '4':
            break
        else:
            print("Invalid option. Try again.")

