from collections import Counter


def filter_ips(input_file_path, output_file_path, allowed_ips):
    ip_count = Counter()

    try:
        with open(input_file_path, 'r') as file:
            for line in file:
                ip = line.split()[0]  # Припускаємо, що IP-адреса є першою частиною рядка
                print(f"Зчитано IP: {ip}")  # Виводимо кожен зчитаний IP

                # Перевіряємо, чи IP з логів є в списку дозволених
                if ip in allowed_ips:
                    ip_count[ip] += 1
                    print(f"Знайдена дозволена IP: {ip}")  # Виводимо повідомлення про знайдену дозволену IP

        if ip_count:
            with open(output_file_path, 'w') as output_file:
                for ip, count in ip_count.items():
                    output_file.write(f"{ip} - {count}\n")
            print(f"Результат збережено у файл {output_file_path}")
        else:
            print("Не знайдено жодної дозволеної IP-адреси в лог-файлі.")

    except FileNotFoundError:
        print(f"❌ Файл не знайдено: {input_file_path}")
    except IOError:
        print(f"❌ Помилка запису до файлу: {output_file_path}")

    return ip_count


# Тестування
allowed_ips = ["83.149.9.216", "93.114.45.13", "50.16.19.13"]  # Додайте дозволені IP
ip_counts = filter_ips("C:/Users/user/Downloads/apache_logs.txt", "C:/Users/user/Downloads/filtered_ips.txt",
                       allowed_ips)
print("Підсумкові IP-адреси з логу:", ip_counts)
