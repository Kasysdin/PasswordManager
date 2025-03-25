import bcrypt
import secrets
import string
import os
import json
import base64
import time
import hmac
import hashlib

# in deze code heb ik een simpele text passwoord manager gemaakt om de lock te kunnen testen en aantonen hoe het werkt
# in de uiteindelijke main code zal dat deel er niet zijn en enkel de lock aspecten (hashing, hmac, key, time-out)

data_file = 'password_manager_data.json'
SECRET_KEY = b'supersecretkey'  # veilig in  environment variable!
FAILED_ATTEMPTS = {}
MAX_ATTEMPTS = 3
TIMEOUT_DURATION = 30


# wachtwoord genereren (
def generate_password(length=16):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in password) and
                any(c.isupper() for c in password) and
                any(c.isdigit() for c in password) and
                any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)):
            return password


# Hash wachtwoord
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return base64.b64encode(hashed_password).decode('utf-8')


# timing attacks voorkomen
def verify_password(stored_hash, password_to_verify):
    decoded_hash = base64.b64decode(stored_hash.encode('utf-8'))
    return hmac.compare_digest(bcrypt.hashpw(password_to_verify.encode('utf-8'), decoded_hash), decoded_hash)


# HMAC berekening
def calculate_hmac(data):
    return hmac.new(SECRET_KEY, json.dumps(data, sort_keys=True).encode(), hashlib.sha256).hexdigest()


# Opslaan gegevens
def save_password_data(account_name, password_hash, key):
    data = {}
    if os.path.exists(data_file) and os.path.getsize(data_file) > 0:
        with open(data_file, 'r') as file:
            try:
                data = json.load(file)
                if 'hmac' in data and data['hmac'] != calculate_hmac(data['accounts']):
                    print("Waarschuwing: Gegevensbestand kan zijn gemanipuleerd!")
                    return False
            except json.JSONDecodeError:
                print("Fout bij het lezen van het bestand. Mogelijk is het beschadigd.")
                return False

    data['accounts'] = data.get('accounts', {})
    data['accounts'][account_name] = {'key': key, 'hash': password_hash}
    data['hmac'] = calculate_hmac(data['accounts'])

    with open(data_file, 'w') as file:
        json.dump(data, file, indent=4)

    return True


# Ophalen gegevens
def retrieve_password(account_name, entered_password):
    if os.path.exists(data_file) and os.path.getsize(data_file) > 0:
        with open(data_file, 'r') as file:
            try:
                data = json.load(file)
                if 'hmac' in data and data['hmac'] != calculate_hmac(data['accounts']):
                    print("Waarschuwing: Gegevensbestand kan zijn gemanipuleerd!")
                    return False
            except json.JSONDecodeError:
                print("Fout bij het lezen van het bestand.")
                return False

        if account_name in data['accounts']:
            stored_hash = data['accounts'][account_name]['hash']
            if verify_password(stored_hash, entered_password):
                return data['accounts'][account_name]['key']
    return False


# Reset account met sleutel
def retrieve_account(account_name, entered_key):
    if os.path.exists(data_file) and os.path.getsize(data_file) > 0:
        with open(data_file, 'r') as file:
            try:
                data = json.load(file)
                if 'hmac' in data and data['hmac'] != calculate_hmac(data['accounts']):
                    print("Waarschuwing: Gegevensbestand kan zijn gemanipuleerd!")
                    return False
            except json.JSONDecodeError:
                print("Fout bij het lezen van het bestand.")
                return False

        if account_name in data['accounts'] and data['accounts'][account_name]['key'] == entered_key:
            new_password = generate_password()
            new_hashed_password = hash_password(new_password)
            new_key = secrets.token_hex(16)

            data['accounts'][account_name]['hash'] = new_hashed_password
            data['accounts'][account_name]['key'] = new_key
            data['hmac'] = calculate_hmac(data['accounts'])

            with open(data_file, 'w') as file:
                json.dump(data, file, indent=4)

            print(f"Account '{account_name}' gereset.")
            print(f"Nieuw wachtwoord: {new_password}")
            print(f"Nieuwe sleutel: {new_key}")
            return True
        else:
            print("Verkeerde sleutel of account bestaat niet.")
            return False


# main
if __name__ == "__main__":
    while True:
        print("1. Maak een nieuw account aan")
        print("2. Verifieer wachtwoord")
        print("3. Reset account met sleutel")
        print("4. Afsluiten")

        choice = input("Kies een optie: ")

        if choice == '1':
            account_name = input("Accountnaam: ")
            password = generate_password()
            key = secrets.token_hex(16)
            hashed_password = hash_password(password)
            if save_password_data(account_name, hashed_password, key):
                print(f"Account '{account_name}' aangemaakt.")
                print(f"Wachtwoord: {password}")
                print(f"Sleutel: {key}")
            else:
                print("Fout bij opslaan.")

        elif choice == '2':
            account_name = input("Accountnaam: ")
            entered_password = input("Wachtwoord: ")
            result = retrieve_password(account_name, entered_password)
            if result:
                print("Correct wachtwoord!")
            else:
                print("Verkeerd wachtwoord.")

        elif choice == '3':
            account_name = input("Accountnaam: ")
            entered_key = input("Sleutel: ")
            retrieve_account(account_name, entered_key)

        elif choice == '4':
            break
        else:
            print("Ongeldige optie. Probeer opnieuw.")
