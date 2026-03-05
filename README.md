# PySecret Application

# Description
This application encrypt text without the need of a password.  
It asks the user 7 personal questions and generates a secure password off of these questions.  
> [!CAUTION]
> This application does not provide the same level of security as standard text encryption methods.  
> Use it at your own risk.  

# Libraries needed to run app with Python
Before running in Python, Libraries below need to be installed:  
- $> `pip install argon2-cffi`
- $> `pip install pynacl`

# parameters.ini
Optionally, this app accepts a 'parameters.ini' file on the root app directory with the parameters below:  

```sh
DEBUG_ON=false                      # debug messages on or off (default = false)
SECRET_EXPIRATION_IN_SECONDS=300    # in how many seconds the secret expires (default = 300)
RESULT_FILE_PATH=                   # default = empty (file on app's root directory). Sample: 'C:\Users\john'
RESULT_FILE_NAME=file.dta           # file name to save or read data from
```

# Executable
To generate executable file (obs: each SO's executable must be generated on that SO.):  
- install `pip install pyinstaller`
- if installed on user profile (not on venv):
```powershell
[Environment]::SetEnvironmentVariable(
  "PATH",
  $env:PATH + ";$env:APPDATA\Python\Python314\Scripts",
  "User")  
```
- close and open powershell again
- generate executable `pyinstaller --onefile --name pySecret pySecret.py`

# TODO List
- Make the python file executable and self-contained.