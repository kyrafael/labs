import hashlib


def generate_file_hashes(*file_paths):
    hashes = {}

    for file_path in file_paths:
        try:
            with open(file_path, 'rb') as file:
                file_content = file.read()
                file_hash = hashlib.sha256(file_content).hexdigest()  # Обчислюємо SHA-256 хеш
                hashes[file_path] = file_hash
        except FileNotFoundError:
            # Просто пропускаємо файл без повідомлення
            pass
        except IOError:
            print(f"❌ Помилка читання файлу: {file_path}")

    return hashes


# Тестування
file_hashes = generate_file_hashes("C:/Users/user/Downloads/apache_logs.txt",
                                   "C:/Users/user/Downloads/another_file.txt")
print(file_hashes)
