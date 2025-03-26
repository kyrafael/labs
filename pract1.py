import json

import requests

response_data = requests.get("https://bank.gov.ua/NBU_Exchange/exchange_site?start=20250317&end=20250321&valcode=eur&json")


print(response_data)
#print (response_data.content)


response_list = json.loads(response_data.content)

exchange_date = []
exchange_rate = []
for item in response_list:
    exchange_date.append(item['exchangedate'])
    exchange_rate.append(item['rate'])
    print(f"Data: {item['exchangedate']}, Rate: {item['rate']}, Currency: {item['enname']}")

### Part 2
#Matplotlib
import matplotlib.pyplot as plt
plt.plot(exchange_date,exchange_rate)
plt.show()
git config --global user.name "kyrafael"
git config --global user.email "ваш_email@example.com"
