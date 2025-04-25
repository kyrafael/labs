from collections import Counter

def word_count(text):
    words = text.split()
    word_dict = dict(Counter(words))  # Підраховуємо кількість кожного слова
    more_than_three = [word for word, count in word_dict.items() if count > 3]  # Слова, які зустрічаються більше 3 разів
    return word_dict, more_than_three

# Тестування
text = "apple banana apple orange banana apple apple orange banana"
word_dict, more_than_three = word_count(text)
print("Словник:", word_dict)
print("Слова, що зустрічаються більше 3 разів:", more_than_three)
