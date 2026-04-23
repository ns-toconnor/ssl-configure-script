@echo off
:: This tool will try to detect common cli tools and will configure the Netskope SSL certificate bundle.
:: Uses the Netskope API to retrieve tenant CA certificates instead of the org key method.

setlocal EnableDelayedExpansion

:: Detect a usable Python interpreter up front (used for API parsing and JSON config edits)
set "PY_CMD="
where python >NUL 2>&1
if %ERRORLEVEL% EQU 0 (
    set "PY_CMD=python"
) else (
    where python3 >NUL 2>&1
    if !ERRORLEVEL! EQU 0 set "PY_CMD=python3"
)
if "!PY_CMD!"=="" (
    echo Error: python is required but was not found on PATH
    exit /b 1
)

:: Get Netskope tenant name
set /p "tenantName=Please provide full Netskope tenant name (ex: tenant-name.goskope.com): "
if "%tenantName%"=="" (
    echo Error: Tenant name cannot be empty
    exit /b 1
)

set "NETSKOPE_CERT_API=https://%tenantName%/api/v2/services/certs/subordinates?purpose=tenant_ca"

:: Set Certificate bundle name and location
set /p "certName=Please provide certificate bundle name [netskope-cert-bundle.pem]: "
if "%certName%"=="" set "certName=netskope-cert-bundle.pem"

set /p "certDir=Please provide certificate bundle location [C:\netskope]: "
if "%certDir%"=="" set "certDir=C:\netskope"

if not exist "%certDir%" (
    echo %certDir% does not exist.
    echo Creating %certDir%
    mkdir "%certDir%"
)

:: Silent-deployment script lives alongside the bundle, not in CWD
set "CONFIGURED_TOOLS_FILE=%certDir%\configured_tools.bat"

:: Check for local Netskope client certificates
set "NS_CLIENT_CERT_DIR=C:\ProgramData\Netskope\STAgent\data"
set "NS_CA_CERT=%NS_CLIENT_CERT_DIR%\nscacert.pem"
set "NS_TENANT_CERT=%NS_CLIENT_CERT_DIR%\nstenantcert.pem"
set "use_local_certs=0"

if exist "%NS_CA_CERT%" if exist "%NS_TENANT_CERT%" (
    echo.
    echo Netskope client is installed. Found local certificates:
    echo.
    echo CA Certificate (nscacert.pem):
    openssl x509 -in "%NS_CA_CERT%" -noout -subject 2>NUL
    echo.
    echo Tenant Certificate (nstenantcert.pem):
    openssl x509 -in "%NS_TENANT_CERT%" -noout -subject 2>NUL
    echo.
    set /p "use_local=Use these local certificates instead of the API? (Y/n): "
    if /i not "!use_local!"=="n" set "use_local_certs=1"
)

:: Get API token for certificate retrieval (only needed if not using local certs)
set "api_token="
if "%use_local_certs%"=="0" (
    if defined NETSKOPE_API_TOKEN (
        echo.
        echo Found NETSKOPE_API_TOKEN environment variable.
        set /p "use_env_token=Use this token? (Y/n): "
        if /i not "!use_env_token!"=="n" set "api_token=%NETSKOPE_API_TOKEN%"
    )

    if "!api_token!"=="" (
        echo.
        :: Read the token via PowerShell so it isn't echoed to the console
        for /f "usebackq tokens=* delims=" %%T in (`powershell -NoProfile -Command "$s = Read-Host -Prompt 'Please provide the Netskope API Bearer token' -AsSecureString; $b = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($s); [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($b)"`) do set "api_token=%%T"
        if "!api_token!"=="" (
            echo Error: API token cannot be empty
            exit /b 1
        )
    )
)

:: Create or update certificate bundle
if exist "%certDir%\%certName%" (
    echo %certName% already exists in %certDir%.
    set /p "recreate=Recreate Certificate Bundle? (y/N): "
    if /i "!recreate!"=="y" (
        call :create_cert_bundle
    )
) else (
    call :create_cert_bundle
)

goto :configure_all

:create_cert_bundle
echo Creating cert bundle

if "%use_local_certs%"=="1" (
    echo Using local Netskope client certificates...
    copy /y "%NS_TENANT_CERT%" "%certDir%\%certName%" >NUL
    type "%NS_CA_CERT%" >> "%certDir%\%certName%"
    echo Netskope certificates added from local client
) else (
    echo Fetching Netskope tenant CA certificates...
    curl -k --connect-timeout 30 --max-time 60 --silent --show-error ^
        -X GET "%NETSKOPE_CERT_API%" ^
        -H "accept: application/json" ^
        -H "Authorization: Bearer %api_token%" ^
        -o "%TEMP%\ns_api_response.json"

    if !ERRORLEVEL! NEQ 0 (
        echo Error: Failed to retrieve certificates from API
        exit /b 1
    )

    :: Extract PEM certificates from JSON response using Python (PY_CMD set at top)
    set "TEMP_FILE=%TEMP%\ns_api_response.json"
    set "CERT_FILE=%TEMP%\ns_certs.pem"

    !PY_CMD! -c "import json,os,sys;f=open(os.environ['TEMP_FILE'],'r');data=json.load(f);f.close();certs=data.get('certificates',[]);[print(c.get('certificate','')) or print(c.get('issuer','')) for c in certs if c] if certs else (print('Error: No certificates found',file=sys.stderr),sys.exit(1))" > "!CERT_FILE!"

    if !ERRORLEVEL! NEQ 0 (
        echo Error: Failed to extract certificates from API response
        del /f "%TEMP%\ns_api_response.json" 2>NUL
        exit /b 1
    )

    :: Check cert file is not empty
    for %%A in ("!CERT_FILE!") do if %%~zA==0 (
        echo Error: No PEM certificates extracted from API response
        del /f "!CERT_FILE!" 2>NUL
        del /f "%TEMP%\ns_api_response.json" 2>NUL
        exit /b 1
    )

    echo Netskope certificates retrieved successfully
    copy /y "!CERT_FILE!" "%certDir%\%certName%" >NUL
    del /f "!CERT_FILE!" 2>NUL
    del /f "%TEMP%\ns_api_response.json" 2>NUL
)

:: Download Mozilla CA bundle and append
echo Downloading Mozilla CA bundle...
curl -k --connect-timeout 30 --max-time 60 --fail --silent --show-error "https://curl.se/ca/cacert.pem" >> "%certDir%\%certName%"
if !ERRORLEVEL! NEQ 0 (
    echo Error: Failed to download Mozilla CA bundle
    exit /b 1
)

echo Certificate bundle created successfully: %certDir%\%certName%
exit /b 0

:configure_all

:: Initialize silent-deployment script (run to replay post-commands + setx calls on another machine)
echo @echo off > "%CONFIGURED_TOOLS_FILE%"
echo :: Silent deployment for configured tools >> "%CONFIGURED_TOOLS_FILE%"

:: ============================================================
:: Configure tools
:: ============================================================

:: Git
echo.
where git >NUL 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Git is installed
    git --version
    for /f "tokens=*" %%P in ('git config --global http.sslCAInfo 2^>NUL') do set "git_current=%%P"
    if "!git_current!"=="%certDir%\%certName%" (
        echo Git already configured
    ) else (
        git config --global http.sslCAInfo "%certDir%\%certName%"
        echo Git configured
        echo git config --global http.sslCAInfo "%certDir%\%certName%" >> "%CONFIGURED_TOOLS_FILE%"
    )
) else (
    echo Git is not installed
)

:: OpenSSL
echo.
where openssl >NUL 2>&1
if %ERRORLEVEL% EQU 0 (
    echo OpenSSL is installed
    openssl version 2>&1
    call :setx_if_needed "OpenSSL" "SSL_CERT_FILE" "%certDir%\%certName%"
) else (
    echo OpenSSL is not installed
)

:: cURL
echo.
where curl >NUL 2>&1
if %ERRORLEVEL% EQU 0 (
    echo cURL is installed
    curl --version
    call :setx_if_needed "cURL" "CURL_CA_BUNDLE" "%certDir%\%certName%"
) else (
    echo cURL is not installed
)

:: Python Requests Library
echo.
where python >NUL 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Python is installed
    python --version 2>&1
    call :setx_if_needed "Python Requests Library" "REQUESTS_CA_BUNDLE" "%certDir%\%certName%"
) else (
    where python3 >NUL 2>&1
    if !ERRORLEVEL! EQU 0 (
        echo Python is installed
        python3 --version 2>&1
        call :setx_if_needed "Python Requests Library" "REQUESTS_CA_BUNDLE" "%certDir%\%certName%"
    ) else (
        echo Python is not installed
    )
)

:: AWS CLI
echo.
where aws >NUL 2>&1
if %ERRORLEVEL% EQU 0 (
    echo AWS CLI is installed
    aws --version 2>&1
    call :setx_if_needed "AWS CLI" "AWS_CA_BUNDLE" "%certDir%\%certName%"
) else (
    echo AWS CLI is not installed
)

:: Google Cloud CLI
echo.
where gcloud >NUL 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Google Cloud CLI is installed
    gcloud --version 2>&1
    gcloud config set core/custom_ca_certs_file "%certDir%\%certName%"
    echo Google Cloud CLI configured
    echo gcloud config set core/custom_ca_certs_file "%certDir%\%certName%" >> "%CONFIGURED_TOOLS_FILE%"
) else (
    echo Google Cloud CLI is not installed
)

:: NodeJS Package Manager (NPM)
echo.
where npm >NUL 2>&1
if %ERRORLEVEL% EQU 0 (
    echo NodeJS Package Manager ^(NPM^) is installed
    npm --version
    npm config set cafile "%certDir%\%certName%"
    echo NodeJS Package Manager ^(NPM^) configured
    echo npm config set cafile "%certDir%\%certName%" >> "%CONFIGURED_TOOLS_FILE%"
) else (
    echo NodeJS Package Manager ^(NPM^) is not installed
)

:: NodeJS
echo.
where node >NUL 2>&1
if %ERRORLEVEL% EQU 0 (
    echo NodeJS is installed
    node --version
    call :setx_if_needed "NodeJS" "NODE_EXTRA_CA_CERTS" "%certDir%\%certName%"
) else (
    echo NodeJS is not installed
)

:: Ruby
echo.
where ruby >NUL 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Ruby is installed
    ruby --version 2>&1
    call :setx_if_needed "Ruby" "SSL_CERT_FILE" "%certDir%\%certName%"
) else (
    echo Ruby is not installed
)

:: PHP Composer
echo.
where composer >NUL 2>&1
if %ERRORLEVEL% EQU 0 (
    echo PHP Composer is installed
    composer --version 2>&1
    composer config --global cafile "%certDir%\%certName%"
    echo PHP Composer configured
    echo composer config --global cafile "%certDir%\%certName%" >> "%CONFIGURED_TOOLS_FILE%"
) else (
    echo PHP Composer is not installed
)

:: Azure CLI (honors REQUESTS_CA_BUNDLE per Microsoft docs — same var as Python Requests)
echo.
where az >NUL 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Azure CLI is installed
    az --version 2>&1
    call :setx_if_needed "Azure CLI" "REQUESTS_CA_BUNDLE" "%certDir%\%certName%"
) else (
    echo Azure CLI is not installed
)

:: Python PIP
echo.
where pip3 >NUL 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Python PIP is installed
    pip3 --version 2>&1
    call :setx_if_needed "Python PIP" "PIP_CERT" "%certDir%\%certName%"
) else (
    where pip >NUL 2>&1
    if !ERRORLEVEL! EQU 0 (
        echo Python PIP is installed
        pip --version 2>&1
        call :setx_if_needed "Python PIP" "PIP_CERT" "%certDir%\%certName%"
    ) else (
        echo Python PIP is not installed
    )
)

:: Oracle Cloud CLI
echo.
where oci >NUL 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Oracle Cloud CLI is installed
    oci --version 2>&1
    call :setx_if_needed "Oracle Cloud CLI" "OCI_CLI_CA_BUNDLE" "%certDir%\%certName%"
) else (
    echo Oracle Cloud CLI is not installed
)

:: Cargo Package Manager
echo.
where cargo >NUL 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Cargo Package Manager is installed
    cargo --version 2>&1
    call :setx_if_needed "Cargo Package Manager" "CARGO_HTTP_CAINFO" "%certDir%\%certName%"
) else (
    echo Cargo Package Manager is not installed
)

:: Yarn
echo.
where yarn >NUL 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Yarn is installed
    yarn --version
    yarn config set httpsCaFilePath "%certDir%\%certName%"
    echo Yarn configured
    echo yarn config set httpsCaFilePath "%certDir%\%certName%" >> "%CONFIGURED_TOOLS_FILE%"
) else (
    echo Yarn is not installed
)

:: Claude CLI
echo.
where claude >NUL 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Claude CLI is installed
    claude --version 2>&1
    call :setx_if_needed "Claude CLI" "NODE_EXTRA_CA_CERTS" "%certDir%\%certName%"
) else (
    echo Claude CLI is not installed
)

:: ============================================================
:: Application-specific configurations (file/config based)
:: ============================================================

:: Azure Storage Explorer
echo.
set "storage_explorer_certs_dir=%LOCALAPPDATA%\Programs\Microsoft Azure Storage Explorer\certs"
if not exist "%storage_explorer_certs_dir%" (
    :: Also check the older/alternative install path
    set "storage_explorer_certs_dir=%USERPROFILE%\AppData\Local\Programs\Microsoft Azure Storage Explorer\certs"
)
if exist "%storage_explorer_certs_dir%" (
    echo Azure Storage Explorer is installed
    if exist "%storage_explorer_certs_dir%\%certName%" (
        fc /b "%certDir%\%certName%" "%storage_explorer_certs_dir%\%certName%" >NUL 2>&1
        if !ERRORLEVEL! EQU 0 (
            echo Azure Storage Explorer already configured with current certificate
        ) else (
            copy /y "%certDir%\%certName%" "%storage_explorer_certs_dir%\" >NUL
            echo Azure Storage Explorer configured
            echo copy /y "%certDir%\%certName%" "%storage_explorer_certs_dir%\" >> "%CONFIGURED_TOOLS_FILE%"
        )
    ) else (
        copy /y "%certDir%\%certName%" "%storage_explorer_certs_dir%\" >NUL
        echo Azure Storage Explorer configured
        echo copy /y "%certDir%\%certName%" "%storage_explorer_certs_dir%\" >> "%CONFIGURED_TOOLS_FILE%"
    )
) else (
    echo Azure Storage Explorer is not installed
)

:: Claude Desktop
echo.
set "claude_desktop_config=%APPDATA%\Claude\claude_desktop_config.json"
set "claude_desktop_app="
if exist "%LOCALAPPDATA%\Programs\claude-desktop\Claude.exe" set "claude_desktop_app=found"
if exist "%ProgramFiles%\Claude\Claude.exe" set "claude_desktop_app=found"
if exist "%LOCALAPPDATA%\Claude\Claude.exe" set "claude_desktop_app=found"

if defined claude_desktop_app (
    echo Claude Desktop is installed

    :: Create config directory if it doesn't exist
    set "claude_desktop_config_dir=%APPDATA%\Claude"
    if not exist "!claude_desktop_config_dir!" mkdir "!claude_desktop_config_dir!"
    if not exist "%claude_desktop_config%" echo {} > "%claude_desktop_config%"

    :: Backup config before modifying
    copy /y "%claude_desktop_config%" "%claude_desktop_config%.backup" >NUL

    set "CERT_PATH=%certDir%\%certName%"
    set "CONFIG_PATH=%claude_desktop_config%"
    !PY_CMD! -c "import json,os,sys;cp=os.environ['CONFIG_PATH'];certp=os.environ['CERT_PATH'].replace('\\','\\\\');f=open(cp,'r');config=json.load(f);f.close();sys.exit(2) if config.get('env',{}).get('NODE_EXTRA_CA_CERTS')==os.environ['CERT_PATH'] else None;config.setdefault('env',{});config['env']['NODE_EXTRA_CA_CERTS']=os.environ['CERT_PATH'];f=open(cp,'w');json.dump(config,f,indent=2);f.close();print('Claude Desktop configured successfully')"

    if !ERRORLEVEL! EQU 2 (
        echo Claude Desktop already configured
    ) else if !ERRORLEVEL! EQU 0 (
        echo Claude Desktop configured
        echo echo Claude Desktop configured with NODE_EXTRA_CA_CERTS >> "%CONFIGURED_TOOLS_FILE%"
    ) else (
        :: Restore backup on failure
        copy /y "%claude_desktop_config%.backup" "%claude_desktop_config%" >NUL 2>NUL
        echo Warning: Failed to configure Claude Desktop
    )

    del /f "%claude_desktop_config%.backup" 2>NUL
    echo Note: Please restart Claude Desktop for changes to take effect
) else (
    echo Claude Desktop is not installed
)

:: VS Code variants
call :configure_vscode "VS Code" "%APPDATA%\Code\User\settings.json"
call :configure_vscode "VS Code Insiders" "%APPDATA%\Code - Insiders\User\settings.json"
call :configure_vscode "Cursor" "%APPDATA%\Cursor\User\settings.json"

echo.
echo ============================================================
echo Configuration complete!
echo.
echo Note: setx changes take effect in NEW console windows (not this one).
echo.
echo For silent deployment on other machines, run:
echo     "%CONFIGURED_TOOLS_FILE%"
echo ============================================================

endlocal
exit /b 0

:: ============================================================
:: Helper functions
:: ============================================================

:: Set a persistent environment variable if not already set to the correct value
:setx_if_needed
:: %~1 - Tool name
:: %~2 - Environment variable name
:: %~3 - Value to set
set "current_val=!%~2!"
if "%current_val%"=="%~3" (
    echo %~1 already configured
) else (
    setx %~2 "%~3" >NUL
    set "%~2=%~3"
    echo %~1 configured
    echo setx %~2 "%~3" >> "%CONFIGURED_TOOLS_FILE%"
)
exit /b 0

:: Configure VS Code variant
:configure_vscode
:: %~1 - Variant name (e.g., "VS Code")
:: %~2 - Settings file path
echo.
if exist "%~2" (
    echo %~1 is installed

    :: Backup settings
    copy /y "%~2" "%~2.backup" >NUL

    set "VSCODE_CONFIG=%~2"
    set "CERT_PATH=%certDir%\%certName%"

    !PY_CMD! -c "import json,re,os,sys;cp=os.environ['VSCODE_CONFIG'];certp=os.environ['CERT_PATH'];f=open(cp,'r');content=f.read();f.close();content=re.sub(r'//.*?$','',content,flags=re.MULTILINE);content=re.sub(r'/\*.*?\*/','',content,flags=re.DOTALL);content=re.sub(r',\s*([}\]])',r'\1',content);settings=json.loads(content);env=settings.get('terminal.integrated.env.windows',{});sys.exit(2) if env.get('NODE_EXTRA_CA_CERTS')==certp else None;settings.setdefault('terminal.integrated.env.windows',{});settings['terminal.integrated.env.windows']['NODE_EXTRA_CA_CERTS']=certp;f=open(cp,'w');json.dump(settings,f,indent=2);f.close();print('configured successfully')"

    if !ERRORLEVEL! EQU 2 (
        echo %~1 already configured
    ) else if !ERRORLEVEL! EQU 0 (
        echo %~1 configured with NODE_EXTRA_CA_CERTS in terminal environment
    ) else (
        :: Restore backup on failure
        copy /y "%~2.backup" "%~2" >NUL 2>NUL
        echo Warning: Failed to configure %~1
    )

    del /f "%~2.backup" 2>NUL
    echo Note: Please restart %~1 for changes to take effect
) else (
    echo %~1 is not installed
)
exit /b 0
