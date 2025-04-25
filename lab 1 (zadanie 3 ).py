def calculate_sell(sell):
    total_value = {}
    for item in sell:
        good_name = item["продукт"]
        quantity = item["кількість"]
        price = item["ціна"]
        value = quantity * price
        if good_name in total_value:
            total_value[good_name] += value
        else:
            total_value[good_name] = value
    return total_value

# Тестування
sales = [
    {"продукт": "apple", "кількість": 10, "ціна": 50},
    {"продукт": "banana", "кількість": 30, "ціна": 20},
    {"продукт": "orange", "кількість": 15, "ціна": 60},
    {"продукт": "grape", "кількість": 5, "ціна":300}
]

# Викликаємо функцію
total_sell_value = calculate_sell(sales)
print("Загальний дохід за продуктом:", total_sell_value)

# Продукти, що принесли більше 1000
list_for_goods = []
for good in total_sell_value:
    print("key:", good)
    print("value:", total_sell_value[good])
    if total_sell_value[good] > 1000:
        list_for_goods.append(good)

print("Продукти з доходом більше 1000:", list_for_goods)
