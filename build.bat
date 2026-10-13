@echo off
rem Compilation de Phare sous Windows.
rem Utilise CMake s'il est installe, sinon gcc (MinGW / MSYS2) directement.
setlocal
where cmake >nul 2>nul
if %errorlevel%==0 (
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release || exit /b 1
  cmake --build build --config Release || exit /b 1
  ctest --test-dir build -C Release --output-on-failure
  goto :eof
)
where gcc >nul 2>nul
if %errorlevel%==0 (
  if not exist build mkdir build
  gcc -std=c11 -O2 -Wall -Wextra -Isrc -o build\phare.exe src\main.c src\http.c src\fs.c -lws2_32 || exit /b 1
  gcc -std=c11 -O2 -Wall -Isrc -o build\test_http.exe tests\test_http.c src\http.c || exit /b 1
  build\test_http.exe
  echo.
  echo Lancez le serveur avec : build\phare.exe
  goto :eof
)
echo Aucun compilateur trouve. Installez MSYS2 (gcc) ou Visual Studio Build Tools + CMake.
echo Un executable pret a l'emploi est aussi fourni dans dist\phare.exe
exit /b 1
