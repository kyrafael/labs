def analyze_log_file(log_file_path):
    try:
        result_dict = {}
        with open(log_file_path) as file:
            for line in file:
                split_list = line.split()

                # Перевірка на те, що є достатньо елементів
                if len(split_list) > 8:
                    status_code = split_list[8]
                    if status_code in result_dict:
                        result_dict[status_code] += 1
                    else:
                        result_dict[status_code] = 1
                else:
                    print("⚠️ Рядок надто короткий або має неочікувану структуру:", line.strip())

    except FileNotFoundError:
        print("❌ Файл не знайдено.")
    except IOError:
        print("❌ Помилка читання файлу.")

    return result_dict


# Виклик функції
res = analyze_log_file("C:/Users/user/Downloads/apache_logs.txt")
print(res)