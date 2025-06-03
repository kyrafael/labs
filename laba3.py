import sqlite3
import hashlib

def create_database():
    """Створює базу даних SQLite3 та таблицю users, якщо вони не існують."""
    conn = sqlite3.connect('user.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            login TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            full_name TEXT
        )
    ''')
    conn.commit()
    conn.close()
    print("Базу даних 'user.db' та таблицю 'users' створено (або вони вже існують).")

def hash_password(password):
    """Хешує пароль за допомогою SHA256."""
    return hashlib.sha256(password.encode()).hexdigest()

def add_user(login, password, full_name):
    """Додає нового користувача до бази даних."""
    conn = sqlite3.connect('user.db')
    cursor = conn.cursor()
    try:
        hashed_password = hash_password(password)
        cursor.execute("INSERT INTO users (login, password, full_name) VALUES (?, ?, ?)",
                       (login, hashed_password, full_name))
        conn.commit()
        print(f"Користувача '{login}' успішно додано.")
    except sqlite3.IntegrityError:
        print(f"Помилка: Користувач з логіном '{login}' вже існує.")
    except Exception as e:
        print(f"Виникла помилка при додаванні користувача: {e}")
    finally:
        conn.close()

def update_password(login, new_password):
    """Оновлює пароль для існуючого користувача."""
    conn = sqlite3.connect('user.db')
    cursor = conn.cursor()
    hashed_new_password = hash_password(new_password)
    cursor.execute("UPDATE users SET password = ? WHERE login = ?",
                   (hashed_new_password, login))
    conn.commit()
    if cursor.rowcount > 0:
        print(f"Пароль для користувача '{login}' успішно оновлено.")
    else:
        print(f"Помилка: Користувача з логіном '{login}' не знайдено.")
    conn.close()

def authenticate_user(login, entered_password):
    """Перевіряє автентифікацію користувача за логіном та паролем."""
    conn = sqlite3.connect('user.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE login = ?", (login,))
    result = cursor.fetchone()
    conn.close()

    if result:
        stored_hashed_password = result[0]
        entered_hashed_password = hash_password(entered_password)
        if stored_hashed_password == entered_hashed_password:
            print(f"Автентифікація для '{login}' успішна.")
            return True
        else:
            print(f"Невірний пароль для '{login}'.")
            return False
    else:
        print(f"Користувача з логіном '{login}' не знайдено.")
        return False

def main_menu():
    """Відображає головне меню програми."""
    create_database() # Переконаємось, що БД існує на початку
    while True:
        print("\n--- Меню управління користувачами ---")
        print("1. Додати нового користувача")
        print("2. Оновити пароль користувача")
        print("3. Перевірити автентифікацію")
        print("4. Вийти")

        choice = input("Оберіть опцію: ")

        if choice == '1':
            login = input("Введіть логін нового користувача: ")
            password = input("Введіть пароль: ")
            full_name = input("Введіть повне ПІБ: ")
            add_user(login, password, full_name)
        elif choice == '2':
            login = input("Введіть логін користувача, чий пароль потрібно оновити: ")
            new_password = input("Введіть новий пароль: ")
            update_password(login, new_password)
        elif choice == '3':
            login = input("Введіть логін для автентифікації: ")
            password = input("Введіть пароль: ")
            authenticate_user(login, password)
        elif choice == '4':
            print("Вихід з програми.")
            break
        else:
            print("Невірний вибір. Спробуйте ще раз.")

if __name__ == "__main__":
    main_menu()