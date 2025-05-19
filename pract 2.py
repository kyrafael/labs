import hashlib
from datetime import datetime

# Базовий клас Користувача
class User:
    def __init__(self, username, password, is_active=True):
        self.username = username
        self.password_hash = self._hash_password(password)
        self.is_active = is_active

    def _hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def verify_password(self, password):
        return self.password_hash == self._hash_password(password)

# Підклас Адміністратор
class Administrator(User):
    def __init__(self, username, password, permissions=None):
        super().__init__(username, password)
        self.permissions = permissions if permissions else []

# Підклас Звичайного Користувача
class RegularUser(User):
    def __init__(self, username, password, last_login=None):
        super().__init__(username, password)
        self.last_login = last_login

    def update_last_login(self):
        self.last_login = datetime.now()

# Підклас Гість
class GuestUser(User):
    def __init__(self, username):
        super().__init__(username, "guest", is_active=False)
        self.limited_access = True

# Клас Контролю Доступу
class AccessControl:
    def __init__(self):
        self.users = {}

    def add_user(self, user):
        self.users[user.username] = user

    def authenticate_user(self, username, password):
        user = self.users.get(username)
        if user and user.verify_password(password) and user.is_active:
            if isinstance(user, RegularUser):
                user.update_last_login()
            return user
        return None

# === Основна програма ===

if __name__ == "__main__":
    ac = AccessControl()

    # Додаємо деяких користувачів
    admin = Administrator("admin1", "securepass")
    regular = RegularUser("user1", "mypassword")
    guest = GuestUser("guest1")
    guest.is_active = True

    ac.add_user(admin)
    ac.add_user(regular)
    ac.add_user(guest)

    # Запит на введення логіну та пароля
    print("=== Авторизація користувача ===")
    username_input = input("Ім'я користувача: ")
    password_input = input("Пароль: ")

    user = ac.authenticate_user(username_input, password_input)

    if user:
        print(f"✅ Успішна автентифікація: {user.username}")
    else:
        print("❌ Автентифікація не вдалася: неправильне ім’я користувача або пароль.")
