import win32com.client, os
import msvcrt
import sys
import subprocess
import signal

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def show_menu():
    clear_console()
    print("=" * 50)
    print("       Discord Presence AutoStart Manager")
    print("=" * 50)
    print("1 - Добавить в автозапуск")
    print("2 - Удалить из автозапуска")
    print("=" * 50)
    print("Выберите вариант (1 или 2): ", end="", flush=True)

def get_single_key_input():
    """Получает ввод одной клавиши без необходимости нажимать Enter"""
    while True:
        key = msvcrt.getch().decode('utf-8', errors='ignore')
        if key in ['1', '2']:
            return key
        else:
            # Если нажата неверная клавиша, очищаем консоль и показываем меню заново
            clear_console()
            show_menu()

def kill_pythonw_processes():
    """Завершает все процессы pythonw.exe"""
    try:
        # Используем taskkill для завершения всех процессов pythonw.exe
        result = subprocess.run(
            ['taskkill', '/f', '/im', 'pythonw.exe'],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        if result.returncode == 0:
            print('[+] Все процессы pythonw.exe завершены')
        else:
            if "не найдены" in result.stdout or "not found" in result.stdout:
                print('[!] Процессы pythonw.exe не найдены')
            else:
                print(f'[!] Не удалось завершить процессы pythonw.exe: {result.stderr}')
    except Exception as e:
        print(f'[-] Ошибка при завершении процессов pythonw.exe: {e}')

def run_task_immediately(task_name):
    """Запускает задачу немедленно"""
    try:
        scheduler = win32com.client.Dispatch('Schedule.Service')
        scheduler.Connect()
        root_folder = scheduler.GetFolder('\\')

        # Получаем задачу и запускаем ее
        task = root_folder.GetTask(task_name)
        task.Run('')
        print('[+] Задача запущена')
    except Exception as e:
        print(f'[-] Не удалось запустить задачу: {e}')

def create_task(task_name, program_path, arguments="", working_directory=""):
    scheduler = win32com.client.Dispatch('Schedule.Service')
    scheduler.Connect()
    root_folder = scheduler.GetFolder('\\')

    # Создание объекта задачи
    task = scheduler.NewTask(0)

    # Настройка основных параметров задачи
    task.RegistrationInfo.Description = task_name
    task.RegistrationInfo.Author = "LUCKYBANANA5894"
    task.Principal.RunLevel = 1

    # Создание объекта действия
    action = task.Actions.Create(0)
    action.Path = program_path
    action.Arguments = arguments
    action.WorkingDirectory = working_directory

    # Добавление триггера
    trigger = task.Triggers.Create(9)  # 9 соответствует триггеру 'At logon'
    trigger.Enabled = True

    # Добавление задачи в папку корневой задачи
    try:
        root_folder.RegisterTaskDefinition(
            task_name,
            task,
            6,  # 6 означает 'CreateOrUpdate' задачу
            '', '',  # Пустые строки пользователя и пароля
            3,  # Тип входа 'S4U'
        )
        print('[+] Discord presence успешно добавлено в автозапуск')

        # Запускаем задачу после добавления
        print('[+] Запуск задачи...')
        run_task_immediately(task_name)

    except Exception as e:
        print(f'[-] Запустите от имени администратора. Ошибка: {e}')

def delete_task(task_name):
    """Удаляет задачу из планировщика"""
    try:
        scheduler = win32com.client.Dispatch('Schedule.Service')
        scheduler.Connect()
        root_folder = scheduler.GetFolder('\\')

        # Завершаем процессы pythonw перед удалением
        print('[+] Завершение процессов pythonw.exe...')
        kill_pythonw_processes()

        # Удаляем задачу
        root_folder.DeleteTask(task_name, 0)
        print('[+] Discord presence успешно удалено из автозапуска')

    except Exception as e:
        if "Система не может найти указанный файл" in str(e) or "The system cannot find the file specified" in str(e):
            print('[-] Задача не найдена в автозапуске')
            # Все равно пытаемся завершить процессы pythonw
            print('[+] Завершение процессов pythonw.exe...')
            kill_pythonw_processes()
        else:
            print(f'[-] Запустите от имени администратора. Ошибка: {e}')

def check_task_exists(task_name):
    """Проверяет существует ли задача"""
    try:
        scheduler = win32com.client.Dispatch('Schedule.Service')
        scheduler.Connect()
        root_folder = scheduler.GetFolder('\\')
        task = root_folder.GetTask(task_name)
        return True
    except:
        return False

def main():
    task_name = "Discord Presence"
    working_directory = os.getcwd()
    arguments = "main.py"
    program_path = fr'"{working_directory}\venv\Scripts\pythonw.exe"'

    # Проверяем существование pythonw.exe
    pythonw_path = os.path.join(working_directory, "venv", "Scripts", "pythonw.exe")
    if not os.path.exists(pythonw_path):
        print(f'[-] Ошибка: pythonw.exe не найден по пути: {pythonw_path}')
        print('\nНажмите любую клавишу для выхода...')
        msvcrt.getch()
        return

    # Показываем меню
    show_menu()

    # Получаем выбор пользователя
    choice = get_single_key_input()

    # Выполняем выбранное действие
    if choice == '1':
        print("1")  # Показываем выбранный вариант
        print("\nДобавление в автозапуск...")

        # Проверяем, не существует ли уже задача
        if check_task_exists(task_name):
            print('[!] Задача уже существует в автозапуске')
            response = input('Хотите перезаписать? (y/n): ').lower()
            if response != 'y':
                print('Отменено пользователем')
                return

        create_task(task_name, program_path, arguments, working_directory)

    elif choice == '2':
        print("2")  # Показываем выбранный вариант
        print("\nУдаление из автозапуска...")
        delete_task(task_name)

    # Ждем нажатия любой клавиши перед завершением
    print("\nНажмите любую клавишу для выхода...")
    msvcrt.getch()

if __name__ == "__main__":
    main()