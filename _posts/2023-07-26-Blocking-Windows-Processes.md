Sometimes, there are processes that spinup automatically on Windows that you don't want to run. Maybe its because you have a number of HDDs attached as data storage, and every once in a while some process starts spinning them all up. Maybe these disks are really loud, and you find it annoying that suddenly they start spinning up when you aren't accessing them.

This is exactly the behaviour I was getting from Windows Telemetry, specifically the `compattelrunner.exe` file. A few years ago, I wrote a simple python script that I called "telemetrykiller.py". Here it is in all its glory:

```python
import os
import time

while True:
    # Return value when both are dead is 128, else 0.
    ret = os.system("taskkill /im SearchUI.exe /im compattelrunner.exe /f")
    if not ret:
        print(time.asctime())
    time.sleep(30)
```

A seriously impressive script, I know. I would then launch this script as Admin every once in a while, but it was far from automated.

I decided to revisit this problem because I was tired of launching the script, and I didn't want a python process running all the time. There had to be a better way than polling. I searched around to see if there was some sort of Event queue I could join to see when processes are launched, but then stumbled across this registry key: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`

# How does it work?

The `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` registry key allows you specify debuggers for executables. You add a subkey with your executable, and in that key you can add a `REG_SZ` value with the name "debugger", and the data contains the file/path of your debugger.

I wrote a small program called `processblocker.exe` to fill in as that debugger value. Once registered as the debugger, now my program is responsible for launching the executable. So, it simply doesn't launch it. Process blocked!

# The Code

Maintained at: [https://github.com/guffre/processblocker/](https://github.com/guffre/processblocker/?ref=guffre.com)

```c
//compile: cl processblocker.c
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

const char OPTIONS_KEY[] = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";
const char PROCESSBLOCKER[] = "processblocker.exe";

BOOL CreateKey(LPCSTR IMAGE_KEY);
BOOL DeleteKey(LPCSTR IMAGE_KEY);
VOID ListKeys(LPCSTR KEYNAME);
VOID LogData(int argc, char *argv[]);

void __cdecl main(int argc, char *argv[]) 
{
    LPSTR IMAGE_KEY = NULL;
    DWORD keysize;
    // If there are two arguments and the second argument is valid (contains ".exe")
    if (argc == 3 && strstr(argv[2], ".exe")) {
        // Create string of desired registry key. argv[2] is the executable name
        keysize = sizeof(OPTIONS_KEY) + strlen(argv[2]) + 2;
        IMAGE_KEY = calloc(keysize, sizeof(char));
        snprintf(IMAGE_KEY, keysize, "%s%s", OPTIONS_KEY, argv[2]);

        // Add a key if the argument is "-a"
        if (!strcmp(argv[1], "-a")) {
            printf("Creating key: %s\n", IMAGE_KEY);
            if (CreateKey(IMAGE_KEY)) {
                printf("%s blocking setup was successful.\n", argv[2]);
            }
            else {
                printf("Error setting up blocking for %s\n", argv[2]);
            }
            goto cleanup;
        }
        // Remove a key if the argument is "-r" or "-d"
        else if ( !(strcmp(argv[1], "-r")) || !(strcmp(argv[1], "-d")) ) {
            printf("Deleting key: %s\n", IMAGE_KEY);
            if (DeleteKey(IMAGE_KEY)) {
                printf("%s unblocking setup was successful.\n", argv[2]);
            }
            else {
                printf("Error unblocking %s. (It might not have been blocked).\n", argv[2]);
            }
            goto cleanup;
        }
    }
    else if (argc == 2 && !(strcmp(argv[1], "-l")) ) {
        ListKeys(OPTIONS_KEY);
        return;
    }
    printf("Usage:\n");
    printf("\t(block):   %s -a <filename_to_block>\n", argv[0]);
    printf("\t(unblock): %s -[rd] <filename_to_unblock>\n", argv[0]);
    printf("\t(list): %s -l\n", argv[0]);
    // Log the fact the executable was run. Records argv arguments
    LogData(argc, argv);
    cleanup:
    if (IMAGE_KEY) 
        free(IMAGE_KEY);
}

BOOL CreateKey(LPCSTR IMAGE_KEY) {
    BOOL success;
    DWORD err;
    HKEY hKey = NULL;

    success = FALSE;
    if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, IMAGE_KEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS)
    {
        err = RegSetValueEx(hKey, "debugger", 0, REG_SZ, PROCESSBLOCKER, sizeof(PROCESSBLOCKER));
        if (ERROR_SUCCESS != err)
        {
            printf("Error setting debugger value for key: %s\n", IMAGE_KEY);
            goto cleanup;
        }
    }
    else {
        printf("Error creating key: %s\n", IMAGE_KEY);
        goto cleanup;
    }
    success = TRUE;
    cleanup:
    if (hKey)
        RegCloseKey(hKey);
    return success;
}

BOOL DeleteKey(LPCSTR IMAGE_KEY) {
    BOOL success = FALSE;

    if (RegDeleteKeyEx(HKEY_LOCAL_MACHINE, IMAGE_KEY, KEY_WOW64_32KEY, 0) == ERROR_SUCCESS) {
        printf("Deleted 32-bit Registry Key: %s\n", IMAGE_KEY);
        success = TRUE;
    }
    if (RegDeleteKeyEx(HKEY_LOCAL_MACHINE, IMAGE_KEY, KEY_WOW64_64KEY, 0) == ERROR_SUCCESS) {
        printf("Deleted 64-bit Registry Key: %s\n", IMAGE_KEY);
        success = TRUE;
    }
    return success;
}

VOID ListKeys(LPCSTR KEYNAME) {
    HKEY hKey;
    HKEY hSubKey;

    CHAR     achKey[MAX_KEY_LENGTH];   // buffer for subkey name
    DWORD    cbName;                   // size of name string 
    DWORD    cSubKeys;                 // number of subkeys 
    DWORD    cValues;                  // number of values for key 

    DWORD i, j; 

    LPSTR data;
    DWORD data_size;
    CHAR  achValue[MAX_VALUE_NAME]; 
    DWORD cchValue = MAX_VALUE_NAME;

    CHAR SUBKEY[MAX_VALUE_NAME];

    if( RegOpenKeyEx( HKEY_LOCAL_MACHINE, KEYNAME, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        printf("Error opening key: %s\n", KEYNAME);
        return;
    }

    // Query the OPTIONS_KEY in order to get count of subkeys 
    RegQueryInfoKey(
        hKey,           // key handle 
        NULL,           // buffer for class name 
        NULL,           // size of class string 
        NULL,           // reserved 
        &cSubKeys,      // number of subkeys 
        NULL,           // longest subkey size 
        NULL,           // longest class string 
        NULL,           // number of values for this key 
        NULL,           // longest value name 
        NULL,           // longest value data 
        NULL,           // security descriptor 
        NULL);          // last write time 

    // Enumerate the subkeys, until RegEnumKeyEx fails.
    data = calloc(MAX_VALUE_NAME, sizeof(char));
    for (i = 0; i < cSubKeys; i++) {
        cbName = MAX_KEY_LENGTH;
        if (RegEnumKeyEx(hKey, i, achKey, &cbName, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            // Create new string representing the subkey
            memset(SUBKEY, 0, sizeof(SUBKEY));
            strcat_s(SUBKEY, sizeof(SUBKEY), KEYNAME);
            strcat_s(SUBKEY, sizeof(SUBKEY), achKey);

            // Open the subkey to enumerate its values
            if( RegOpenKeyEx( HKEY_LOCAL_MACHINE, SUBKEY, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                // This pulls out the number of values, as well as the max data size
                if (RegQueryInfoKey(hSubKey, NULL, NULL, NULL, NULL, NULL, NULL, &cValues, NULL, &data_size, NULL, NULL) == ERROR_SUCCESS) {
                    // Make sure we have enough buffer to receive the data
                    if (data_size > MAX_VALUE_NAME) {
                        data = realloc(data, data_size); // This is "bad", but program will exit immediately after this return if it fails
                        if (data == NULL) {
                            printf("Error allocating memory!\n");
                            return;
                        }
                    }
                    // Enumerate the key values. We are looking for the "debugger" value
                    for (j = 0; j < cValues; j++) { 
                        cchValue = MAX_VALUE_NAME; 
                        achValue[0] = '\0'; 
                        memset(data, 0, data_size);
                        if (RegEnumValue(hSubKey, j, achValue, &cchValue, NULL, NULL, data, &data_size) == ERROR_SUCCESS) {
                            if ( !(_stricmp("debugger", achValue)) ) {
                                // Found a debugger value, pull the data portion out:
                                printf("%s:\n value: %s\n data: %s\n", achKey, achValue, data);
                            }
                        }
                    }
                }
                else
                    printf("Error getting info from subkey: %s\n", SUBKEY);
            }
            else
                printf("Error opening subkey: %s\n", SUBKEY);
        }
    }
    if (data)
        free(data);
}

VOID LogData(int argc, char *argv[]) {
    SYSTEMTIME st;
    HANDLE hFile;
    BOOL bErrorFlag;
    LPSTR dataBuf;
    int buf_size;
    int i;

    GetSystemTime(&st);

    hFile = CreateFile("C:\\Windows\\Temp\\processblocker.log", // name of the file
                       FILE_APPEND_DATA,       // open for appending
                       0,                      // do not share
                       NULL,                   // default security
                       OPEN_ALWAYS,            // create file if it doesn't exist, open if it does
                       FILE_ATTRIBUTE_NORMAL,  // normal file
                       NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return;
    }

    // buf_size is the max size of the buffer. 120 bytes (20 for the date, 100 just because), plus 1 byte for each argument (accounts for the ":" delimiter)
    buf_size = 120 + argc;
    for (i = 0; i < argc; i++) {
        buf_size += strlen(argv[i]);
    }
    // Integer overflow. Weird for argv... lets log 16kb
    if (buf_size <= 0)
        buf_size = 1024 * 16;

    // Allocate the buffer
    dataBuf = calloc(buf_size, sizeof(char));

    // Add timestamp and data to buffer. This format string (ASCII) has a length of 20 bytes
    snprintf(dataBuf, buf_size, "%04d-%02d-%02d:%02d:%02d:%02d:", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    for (i = 0; i < argc; i++) {
        strcat_s(dataBuf, buf_size, argv[i]);
        strcat_s(dataBuf, buf_size, ":");
    }
    strcat_s(dataBuf, buf_size, "\n");

    // Write the log
    bErrorFlag = WriteFile( 
                    hFile,           // open file handle
                    dataBuf,      // start of data to write
                    strlen(dataBuf),  // number of bytes to write
                    NULL, // number of bytes that were written
                    NULL);            // no overlapped structure

    if(dataBuf)
        free(dataBuf);
    CloseHandle(hFile);
}
```
