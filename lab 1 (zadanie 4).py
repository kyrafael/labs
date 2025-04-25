def add_task(tasks, task_name, status):
    tasks[task_name] = status

def remove_task(tasks, task_name):
    if task_name in tasks:
        del tasks[task_name]

def change_task_status(tasks, task_name, status):
    if task_name in tasks:
        tasks[task_name] = status

def waiting_tasks(tasks):
    return [task for task, status in tasks.items() if status == "очікує"]

# Тестування
tasks = {
    "Задача 1": "в процесі",
    "Задача 2": "виконано",
    "Задача 3": "очікує"
}

add_task(tasks, "Задача 4", "в процесі")
change_task_status(tasks, "Задача 1", "виконано")
remove_task(tasks, "Задача 2")

print("Оновлений список задач:", tasks)
print("Задачі, які очікують:", waiting_tasks(tasks))
