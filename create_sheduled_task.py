import win32com.client, os

def create_task(task_name, program_path, arguments="", working_directory=""):
	scheduler = win32com.client.Dispatch('Schedule.Service')
	scheduler.Connect()
	root_folder = scheduler.GetFolder('\\')
	
	# Создание объекта задачи
	task = scheduler.NewTask(0)
	
	# Настройка основных параметров задачи
	task.RegistrationInfo.Description = task_name
	task.RegistrationInfo.Author = "plowside"
	
	# Создание объекта действия
	action = task.Actions.Create(0)
	action.Path = program_path
	action.Arguments = arguments
	action.WorkingDirectory = working_directory
	
	# Добавление триггера
	trigger = task.Triggers.Create(9)  # 9 corresponds to 'At logon' trigger
	trigger.Enabled = True
	
	# Добавление задачи в папку корневой задачи
	root_folder.RegisterTaskDefinition(
		task_name,
		task,
		6,  # 6 stands for 'CreateOrUpdate' task
		'', '',  # Empty user and password strings
		3,  # 'S4U' task logon type
	)

# Пример использования
if __name__ == "__main__":
	task_name = "Discord Presence"
	working_directory = os.getcwd()
	arguments = "main.py"
	
	program_path = fr'"{working_directory}\venv\Scripts\pythonw.exe"'
	create_task(task_name, program_path, arguments, working_directory)