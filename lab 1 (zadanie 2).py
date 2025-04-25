def update_inventory(inventory, product, quantity):
    if product in inventory:
        inventory[product] += quantity  # Оновлюємо кількість продукту
    else:
        inventory[product] = quantity  # Додаємо новий продукт

def low_stock_products(inventory, threshold=5):
    return [product for product, quantity in inventory.items() if quantity < threshold]

# Тестування
inventory = {
    "apple": 10,
    "banana": 2,
    "orange": 3,
    "grape": 4
}

update_inventory(inventory, "banana", 3)  # Оновлюємо кількість бананів
update_inventory(inventory, "kiwi", 5)  # Додаємо новий продукт

print("Оновлений інвентар:", inventory)
print("Продукти, кількість яких менше 5:", low_stock_products(inventory))
