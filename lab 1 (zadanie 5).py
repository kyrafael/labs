import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def authenticate_user(users, login, password):
    if login in users:
        stored_password = users[login]['password']
        if stored_password == hash_password(password):
            return True
    return False

users = {
    'Ruby': {'password': hash_password('Ruby2005'), 'full_name': 'Ruby Mathews'},
    'Matt': {'password': hash_password('matt_clarke123'), 'full_name': 'Matt Clarke'}
}

login = input('Enter your login: ')
password = input('Enter your password: ')

if authenticate_user(users, login, password):
    print("Authentication successful")
else:
    print("Authentication failed")