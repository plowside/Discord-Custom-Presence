chcp 65001 > nul
@echo off
title Discord Presence Setup
color 0A

echo ==================================================
echo [*] Проверка виртуального окружения...
echo ==================================================
if not exist "venv\" (
  echo [*] Виртуальное окружение не найдено. Создаю...
  python -m venv venv
  if %ERRORLEVEL% neq 0 (
    echo [-] Ошибка при создании виртуального окружения!
    pause
    exit /b 1
  )
  echo [+] Виртуальное окружение успешно создано.
) else (
  echo [+] Виртуальное окружение уже существует.
)

echo.
echo ==================================================
echo [*] Активация виртуального окружения...
echo ==================================================
call venv\Scripts\activate

echo.
echo ==================================================
echo [*] Установка зависимостей...
echo ==================================================
pip install -r requirements.txt
if %ERRORLEVEL% neq 0 (
  echo [-] Ошибка при установке зависимостей!
  pause
  deactivate
  exit /b 1
)
echo [+] Зависимости установлены.

echo.
echo ==================================================
echo [*] Настройка автозапуска Discord Presence...
echo ==================================================
powershell -Command "Start-Process -FilePath 'venv\Scripts\python.exe' -ArgumentList 'create_sheduled_task.py' -Verb RunAs"
if %ERRORLEVEL% neq 0 (
  echo [-] Ошибка при добавлении задачи в планировщик!
  pause
  deactivate
  exit /b 1
)
echo [+] Discord Presence успешно добавлен в автозапуск.

echo.
echo ==================================================
echo [*] Завершено! Нажмите любую клавишу для выхода.
echo ==================================================
pause
deactivate
exit
