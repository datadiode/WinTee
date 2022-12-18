#include <windows.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <intrin.h>

#include "git-describe.h"

// lstrlenA(), lstrlenW() are evil in that they silently catch access violations
#pragma intrinsic(strlen, wcslen)

// Reinvent memset() to avoid a CRT dependency
#pragma function(memset)

void *memset(void *p, int c, size_t n)
{
    __stosb((unsigned char *)p, (unsigned char)c, n);
    return p;
}

enum Buffer
{
    bufFormatMain = 0,
    bufFormatStdOut,
    bufFormatStdErr,
    bufLastErrorMain,
    bufLastErrorStdOut,
    bufLastErrorStdErr,
    bufCount
};

const DWORD c_PipeBufferSize = 0x1000;

DWORD  g_cchBufSize[bufCount] = {0};
LPSTR  g_pszBuffer[bufCount] = {NULL};
HANDLE g_hStdOut = INVALID_HANDLE_VALUE;
HANDLE g_hStdErr = INVALID_HANDLE_VALUE;
HANDLE g_hLogFile = INVALID_HANDLE_VALUE;
HANDLE g_hLogFileMutex = INVALID_HANDLE_VALUE;

void ExpandBuffer(Buffer buf, DWORD cchReqSize = 0)
{
    if( cchReqSize == 0 )
        cchReqSize = (g_cchBufSize[buf] + 1000) * 2;

    if( cchReqSize < g_cchBufSize[buf] )
        return;

    if (cchReqSize > 0xFFFFFF)
    {
        FatalAppExitW(0, L"ExpandBuffer() failed: limit exceeded");
    }

    g_pszBuffer[buf] = (LPSTR)LocalFree(g_pszBuffer[buf]);
    if( g_pszBuffer[buf] != NULL )
    {
        FatalAppExitW(0, L"ExpandBuffer() failed: can't free");
    }

    g_pszBuffer[buf] = (LPSTR)LocalAlloc(LPTR, cchReqSize);
    if( g_pszBuffer[buf] == NULL )
    {
        FatalAppExitW(0, L"ExpandBuffer() failed: can't allocate");
    }

    g_cchBufSize[buf] = cchReqSize;
}

LPCSTR Format(Buffer buf, LPCSTR szFormat, ...)
{
    va_list arglist;
    va_start(arglist, szFormat);

    while( wvnsprintfA( g_pszBuffer[buf], g_cchBufSize[buf], szFormat, arglist ) < 0 )
        ExpandBuffer(buf);

    va_end(arglist);

    return g_pszBuffer[buf];
}

LPCSTR GetLastErrorMessage(Buffer buf, DWORD dwError = GetLastError())
{
    LPVOID pvMsgBuf = NULL;

    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dwError,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
        (LPSTR) &pvMsgBuf,
        0,
        NULL
    );

    DWORD d = strlen( (LPCSTR) pvMsgBuf );
    ExpandBuffer( buf, d + 1 );
    StringCchCopyA( g_pszBuffer[buf], g_cchBufSize[buf], (LPCSTR) pvMsgBuf );

    LocalFree( pvMsgBuf );

    return g_pszBuffer[buf];
}

void LogPrint(LPCSTR szOutput)
{
    if( g_hLogFile == INVALID_HANDLE_VALUE )
        return;

    if( SetFilePointer( g_hLogFile, 0, NULL, FILE_END ) == -1 )
        return;

    DWORD dwBytesWritten = 0;
    WriteFile( g_hLogFile, szOutput, strlen(szOutput), &dwBytesWritten, NULL );
}

void ConPrint(LPCSTR szOutput, bool fLogFileQuiet = true)
{
    DWORD dwBytesWritten = 0;
    WriteFile( g_hStdOut, szOutput, strlen(szOutput), &dwBytesWritten, NULL );
    if( !fLogFileQuiet )
        LogPrint( szOutput );
}

struct ListenerParameters
{
    HANDLE hReadPipe;
    LPBYTE pBuffer;
    HANDLE hWritePipe;
    BOOL   fConsoleOn;
    BOOL   fLogFileOn;
    Buffer bufFormat;
    Buffer bufLastError;
};

DWORD WINAPI ListenerThread(LPVOID lpParameter)
{
    DWORD dwBytesRead;
    DWORD dwBytesWritten;
    DWORD dwRetCode = ERROR_SUCCESS;
    ListenerParameters* pParameters = (ListenerParameters*) lpParameter;

    //
    // Look for output from the child and pass it on to the console and
    // the log file.
    //
    while( ReadFile(pParameters->hReadPipe, pParameters->pBuffer, c_PipeBufferSize, &dwBytesRead, NULL) )
    {
        if( pParameters->fConsoleOn )
        {
            if( !WriteFile(pParameters->hWritePipe, pParameters->pBuffer, dwBytesRead, &dwBytesWritten, NULL) )
            {
                ConPrint(Format(pParameters->bufFormat, "Error writing to console:\n%s\n",
                    GetLastErrorMessage(pParameters->bufLastError)));
                dwRetCode = GetLastError();
            }
        }

        if( g_hLogFile != INVALID_HANDLE_VALUE &&
            pParameters->fLogFileOn )
        {
            if( WaitForSingleObject(g_hLogFileMutex, INFINITE) != WAIT_OBJECT_0 )
                break;

            if( SetFilePointer( g_hLogFile, 0, NULL, FILE_END ) == -1 )
            {
                ReleaseMutex(g_hLogFileMutex);

                ConPrint(Format(pParameters->bufFormat, "Error seeking to end of log file:\n%s\n",
                    GetLastErrorMessage(pParameters->bufLastError)));
                dwRetCode = GetLastError();
            }

            if( !WriteFile(g_hLogFile, pParameters->pBuffer, dwBytesRead, &dwBytesWritten, NULL) )
            {
                ConPrint(Format(pParameters->bufFormat, "Error writing to log file:\n%s\n",
                    GetLastErrorMessage(pParameters->bufLastError)));
                dwRetCode = GetLastError();
            }

            ReleaseMutex(g_hLogFileMutex);
        }
    }

    return dwRetCode;
}

static LPWSTR PathGetAndRemoveArgsW(LPWSTR p)
{
    LPWSTR q = PathGetArgsW(p);
    PathRemoveArgsW(p);
    return q + StrSpnW(q, L" \t\r\n");
}

extern "C" void mainCRTStartup()
{
    static const WCHAR szCmdPrefix[] = L"cmd.exe /x/c ";

    LPWSTR pszArgs = PathGetArgsW(GetCommandLineW());

    DWORD   dwRetCode = ERROR_INVALID_FUNCTION;
    LPWSTR  pszChildCmdLine = NULL;
    DWORD   cchChildCmdLine = 0;

    STARTUPINFOW ChildStartupInfo;

    WCHAR szMaxPathBuffer[MAX_PATH];
    DWORD cchReqBufSize;

    SECURITY_ATTRIBUTES saAttr;

    HANDLE hStdOutReadPipe = INVALID_HANDLE_VALUE;
    HANDLE hStdOutReadPipeDup = INVALID_HANDLE_VALUE;
    HANDLE hStdOutWritePipe = INVALID_HANDLE_VALUE;

    HANDLE hStdErrReadPipe = INVALID_HANDLE_VALUE;
    HANDLE hStdErrReadPipeDup = INVALID_HANDLE_VALUE;
    HANDLE hStdErrWritePipe = INVALID_HANDLE_VALUE;

    HANDLE hStdOutListenerThread = INVALID_HANDLE_VALUE;
    HANDLE hStdErrListenerThread = INVALID_HANDLE_VALUE;

    PROCESS_INFORMATION ChildProcessInfo;
    ZeroMemory(&ChildProcessInfo, sizeof(ChildProcessInfo));
    ChildProcessInfo.hProcess = INVALID_HANDLE_VALUE;
    ChildProcessInfo.hThread = INVALID_HANDLE_VALUE;

    BYTE  StdOutPipeBuffer[c_PipeBufferSize];
    BYTE  StdErrPipeBuffer[c_PipeBufferSize];

    bool  fConsoleOutputOn = true;
    bool  fLogFileOutputOn = true;
    bool  fConsoleErrorOn = true;
    bool  fLogFileErrorOn = true;
    bool  fLogFileAppend = false;
    bool  fLogFileQuiet = false;
    bool  fStopWatch = false;

    WCHAR *szLogFile = 0;
    WCHAR *szPidFile = 0;
    WCHAR *szScriptName = 0;

    //
    // Save off our inherited std handles
    //
    g_hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    g_hStdErr = GetStdHandle(STD_ERROR_HANDLE);

    //
    // Give our string buffers an initial allocation
    //
    ExpandBuffer(bufFormatMain);
    ExpandBuffer(bufFormatStdOut);
    ExpandBuffer(bufFormatStdErr);
    ExpandBuffer(bufLastErrorMain);
    ExpandBuffer(bufLastErrorStdOut);
    ExpandBuffer(bufLastErrorStdErr);

    //
    // Look for switches directed at us
    //
    while (*pszArgs == '-')
    {
        LPWSTR pszSwitch = pszArgs;
        pszArgs = PathGetAndRemoveArgsW(pszArgs);

        if( 0 == StrCmpIW(pszSwitch, L"-version") )
            ConPrint("WinTee " GIT_DESCRIBE "\n");
        else if( 0 == StrCmpIW(pszSwitch, L"-nco") )
            fConsoleOutputOn = false;
        else if( 0 == StrCmpIW(pszSwitch, L"-nlo") )
            fLogFileOutputOn = false;
        else if( 0 == StrCmpIW(pszSwitch, L"-nce") )
            fConsoleErrorOn = false;
        else if( 0 == StrCmpIW(pszSwitch, L"-nle") )
            fLogFileErrorOn = false;
        else if( 0 == StrCmpIW(pszSwitch, L"-nc") ) // shortcut for -nco -nce
            fConsoleOutputOn = fConsoleErrorOn = false;
        else if( 0 == StrCmpIW(pszSwitch, L"-nl") ) // shortcut for -nlo -nle
            fLogFileOutputOn = fLogFileErrorOn = false;
        else if( 0 == StrCmpIW(pszSwitch, L"-pid") )
        {
            if (*pszArgs == L'\0')
            {
                ConPrint("Error: -pid switch specified without associated file name\n");
                dwRetCode = GetLastError();
                goto Error;
            }
            szPidFile = pszArgs;
            pszArgs = PathGetAndRemoveArgsW(pszArgs);
            PathUnquoteSpacesW(szPidFile);
        }
        else if(0 == StrCmpIW(pszSwitch, L"-file"))
        {
            if (*pszArgs == L'\0')
            {
                ConPrint("Error: -file switch specified without associated file name\n");
                dwRetCode = GetLastError();
                goto Error;
            }
            szLogFile = pszArgs;
            pszArgs = PathGetAndRemoveArgsW(pszArgs);
            PathUnquoteSpacesW(szLogFile);
        }
        else if(0 == StrCmpIW(pszSwitch, L"-name"))
        {
            if (*pszArgs == L'\0')
            {
                ConPrint("Error: -file switch specified without associated file name\n");
                dwRetCode = GetLastError();
                goto Error;
            }
            szScriptName = pszArgs;
            pszArgs = PathGetAndRemoveArgsW(pszArgs);
            PathUnquoteSpacesW(szScriptName);
        }
        else if(0 == StrCmpIW(pszSwitch, L"-quiet"))
            fLogFileQuiet = true;
        else if(0 == StrCmpIW(pszSwitch, L"-append"))
            fLogFileAppend = true;
        else if (0 == StrCmpIW(pszSwitch, L"-stopwatch"))
            fStopWatch = true;
        else
        {
            ConPrint("Error: unknown switch specified\n");
            dwRetCode = GetLastError();
            goto Error;
        }
    }

    //
    // Output the current process' PID to the specified file
    //
    if(szPidFile != 0)
    {
        HANDLE const hPidFile = CreateFileW(szPidFile,
            GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hPidFile == INVALID_HANDLE_VALUE)
        {
            ConPrint(Format(bufFormatMain, "Error creating PID file '%ls':\n%s\n",
                szPidFile, GetLastErrorMessage(bufLastErrorMain)));
            dwRetCode = GetLastError();
            goto Error;
        }

        DWORD dwBytesWritten;
        CHAR szPidString[64];
        int len = wnsprintfA(szPidString, _countof(szPidString), "%u", GetCurrentProcessId());
        BOOL ok = WriteFile(hPidFile, szPidString, len, &dwBytesWritten, NULL);
        CloseHandle(hPidFile);

        if (!ok)
        {
            ConPrint(Format(bufFormatMain, "Error writing to PID file:\n%s\n",
                GetLastErrorMessage(bufLastErrorMain)));
            dwRetCode = GetLastError();
            goto Error;
        }
    }

    //
    // Figure out where log file output is going
    //
    if(szLogFile == 0)
    {
        cchReqBufSize = GetEnvironmentVariableW(L"WINTEE_FILE", szMaxPathBuffer, MAX_PATH);
        if(cchReqBufSize > 0 && cchReqBufSize < MAX_PATH)
            szLogFile = szMaxPathBuffer;
    }
    if(szLogFile != 0)
    {
        DWORD dwCreationDisposition = (fLogFileAppend ? OPEN_ALWAYS : CREATE_ALWAYS);
        if( (g_hLogFile = CreateFileW(szLogFile, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, dwCreationDisposition,
            FILE_ATTRIBUTE_NORMAL, NULL ) ) == INVALID_HANDLE_VALUE )
        {
            ConPrint(Format(bufFormatMain, "Error opening log file '%ls':\n%s\n",
                szLogFile, GetLastErrorMessage(bufLastErrorMain)));
            dwRetCode = GetLastError();
            goto Error;
        }
    }

    //
    // Set the bInheritHandle flag so pipe handles are inherited.
    //
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    //
    // Create the output pipe for the child process
    //
    if( !CreatePipe(&hStdOutReadPipe, &hStdOutWritePipe, &saAttr, 0) )
    {
        ConPrint(Format(bufFormatMain, "Error creating output pipe for child process:\n%s\n",
            GetLastErrorMessage(bufLastErrorMain)));
        dwRetCode = GetLastError();
        goto Error;
    }

    if( !DuplicateHandle(GetCurrentProcess(), hStdOutReadPipe,
        GetCurrentProcess(), &hStdOutReadPipeDup, 0,
        FALSE,
        DUPLICATE_SAME_ACCESS) )
    {
        ConPrint(Format(bufFormatMain, "Error creating output pipe for child process:\n%s\n",
            GetLastErrorMessage(bufLastErrorMain)));
        dwRetCode = GetLastError();
        goto Error;
    }

    CloseHandle(hStdOutReadPipe);
    hStdOutReadPipe = INVALID_HANDLE_VALUE;

    //
    // Create the error pipe for the child process
    //
    if( !CreatePipe(&hStdErrReadPipe, &hStdErrWritePipe, &saAttr, 0) )
    {
        ConPrint(Format(bufFormatMain, "Error creating output pipe for child process:\n%s\n",
            GetLastErrorMessage(bufLastErrorMain)));
        dwRetCode = GetLastError();
        goto Error;
    }

    if( !DuplicateHandle(GetCurrentProcess(), hStdErrReadPipe,
        GetCurrentProcess(), &hStdErrReadPipeDup, 0,
        FALSE,
        DUPLICATE_SAME_ACCESS) )
    {
        ConPrint(Format(bufFormatMain, "Error creating output pipe for child process:\n%s\n",
            GetLastErrorMessage(bufLastErrorMain)));
        dwRetCode = GetLastError();
        goto Error;
    }

    CloseHandle(hStdErrReadPipe);
    hStdErrReadPipe = INVALID_HANDLE_VALUE;

    //
    // Set up the startup info
    //
    ZeroMemory( &ChildStartupInfo, sizeof(ChildStartupInfo) );
    ChildStartupInfo.cb = sizeof(ChildStartupInfo);

    //
    // Redirect the output handle
    //
    SetStdHandle(STD_OUTPUT_HANDLE, hStdOutWritePipe);
    SetStdHandle(STD_ERROR_HANDLE, hStdErrWritePipe);

    //
    // Allocate space for the non-constant command line
    //
    cchChildCmdLine = wcslen(szCmdPrefix) + 1 + wcslen(pszArgs);
    pszChildCmdLine = (LPWSTR)LocalAlloc(LPTR, cchChildCmdLine * sizeof(WCHAR));
    if( pszChildCmdLine == NULL )
    {
        ConPrint("Memory allocation error.\n");
        dwRetCode = GetLastError();
        goto Error;
    }

    //
    // Output the script name & command to the log file
    //
    if( szScriptName == 0 )
    {
        cchReqBufSize = GetEnvironmentVariableW(L"WINTEE_NAME", szMaxPathBuffer, MAX_PATH);
        if(cchReqBufSize > 0 && cchReqBufSize < MAX_PATH)
            szScriptName = szMaxPathBuffer;
        else
            szScriptName = L"WINTEE_NAME not set";
    }
    if(!fLogFileQuiet)
        LogPrint(Format(bufFormatMain, "[%ls] %ls\r\n", szScriptName, pszArgs));

    //
    // Try to create the process plainly (without using CMD.EXE)
    //
    StringCchCopyW(pszChildCmdLine, cchChildCmdLine, pszArgs);
    if( !CreateProcessW( NULL, pszChildCmdLine,
        NULL, NULL, TRUE, 0, NULL, NULL,
        &ChildStartupInfo, &ChildProcessInfo ) )
    {
        //
        // Didn't work. Could be a cmd.exe command... Try that.
        //
        StringCchCopyW(pszChildCmdLine, cchChildCmdLine, szCmdPrefix);
        StringCchCatW(pszChildCmdLine, cchChildCmdLine, pszArgs);
        if( !CreateProcessW( NULL, pszChildCmdLine,
            NULL, NULL, TRUE, 0, NULL, NULL,
            &ChildStartupInfo, &ChildProcessInfo ) )
        {
            ConPrint(Format(bufFormatMain, "Error executing command line '%ls':\n%s\n",
                pszArgs, GetLastErrorMessage(bufLastErrorMain)));
            dwRetCode = GetLastError();
            goto Error;
        }
    }

    //
    // Close our copy of the pipe so that ReadFile returns when no one
    // owns the handle anymore.
    //
    CloseHandle(hStdOutWritePipe);
    hStdOutWritePipe = INVALID_HANDLE_VALUE;

    CloseHandle(hStdErrWritePipe);
    hStdErrWritePipe = INVALID_HANDLE_VALUE;

    g_hLogFileMutex = CreateMutex(NULL, FALSE, NULL);

    ListenerParameters StdOutParameters;
    StdOutParameters.bufFormat = bufFormatStdOut;
    StdOutParameters.bufLastError = bufLastErrorStdOut;
    StdOutParameters.fConsoleOn = fConsoleOutputOn;
    StdOutParameters.fLogFileOn = fLogFileOutputOn;
    StdOutParameters.hReadPipe = hStdOutReadPipeDup;
    StdOutParameters.hWritePipe = g_hStdOut;
    StdOutParameters.pBuffer = StdOutPipeBuffer;
    hStdOutListenerThread = CreateThread(NULL, 0, ListenerThread, &StdOutParameters, NULL, NULL);

    ListenerParameters StdErrParameters;
    StdErrParameters.bufFormat = bufFormatStdErr;
    StdErrParameters.bufLastError = bufLastErrorStdErr;
    StdErrParameters.fConsoleOn = fConsoleErrorOn;
    StdErrParameters.fLogFileOn = fLogFileErrorOn;
    StdErrParameters.hReadPipe = hStdErrReadPipeDup;
    StdErrParameters.hWritePipe = g_hStdErr;
    StdErrParameters.pBuffer = StdErrPipeBuffer;
    hStdErrListenerThread = CreateThread(NULL, 0, ListenerThread, &StdErrParameters, NULL, NULL);

    HANDLE rgThreadHandles[2] = { hStdOutListenerThread, hStdErrListenerThread };

    //
    // Wait for the listener threads to end.
    //
    WaitForMultipleObjects(2, rgThreadHandles, TRUE, INFINITE);

    for( int i = 0; i < 2; i++ )
    {
        if( !GetExitCodeThread( rgThreadHandles[i], &dwRetCode ) )
        {
            ConPrint(Format(bufFormatMain, "Error retrieving listener thread exit code.\n"));
            goto Error;
        }

        if( dwRetCode != ERROR_SUCCESS )
        {
            ConPrint(Format(bufFormatMain, "Listener thread returned an error:\n%s\n",
                GetLastErrorMessage(bufLastErrorMain, dwRetCode)));
            goto Error;
        }
    }

    //
    // Make sure child process is dead
    //
    WaitForSingleObject(ChildProcessInfo.hProcess, INFINITE);

    //
    // Grab the exit code from the child process and return that as
    // our exit code as well.
    //
    if( !GetExitCodeProcess(ChildProcessInfo.hProcess, &dwRetCode) )
    {
        ConPrint(Format(bufFormatMain, "Error retrieving child process' exit code:\n%s\n",
            GetLastErrorMessage(bufLastErrorMain)));
        dwRetCode = GetLastError();
        goto Error;
    }

    if (fStopWatch)
    {
        FILETIME ftc, fte, ftk, ftu;
        if (GetThreadTimes(ChildProcessInfo.hThread, &ftc, &fte, &ftk, &ftu))
        {
            SYSTEMTIME st;
            WCHAR date[80], time[80];
            ConPrint(!FileTimeToSystemTime(&ftc, &st) ?
                "Started:  ?\r\n" : Format(bufFormatMain, "Started:  %ls %ls\r\n",
                GetDateFormatW(LOCALE_INVARIANT, 0, &st, NULL, date, _countof(date)) ? date : L"?",
                GetTimeFormatW(LOCALE_INVARIANT, 0, &st, NULL, time, _countof(time)) ? time : L"?"),
                fLogFileQuiet);
            ConPrint(!FileTimeToSystemTime(&fte, &st) ?
                "Finished: ?\r\n" : Format(bufFormatMain, "Finished: %ls %ls\r\n",
                GetDateFormatW(LOCALE_INVARIANT, 0, &st, NULL, date, _countof(date)) ? date : L"?",
                GetTimeFormatW(LOCALE_INVARIANT, 0, &st, NULL, time, _countof(time)) ? time : L"?"),
                fLogFileQuiet);
            // Format elapsed time using different leading units
            LONGLONG elapsed = reinterpret_cast<LONGLONG &>(fte) - reinterpret_cast<LONGLONG &>(ftc);
            size_t const leading_zeros = 6;
            __stosw(reinterpret_cast<unsigned short *>(time), L'0', leading_zeros);
            if (elapsed & 0xFFE0000000000000LL || // Will shifting left by 10 bits induce loss?
                !StrFormatKBSizeW(__ll_lshift(elapsed, 10), time + leading_zeros, _countof(time) - leading_zeros)) // slightly abusive
            {
                time[leading_zeros] = '\0'; // Have StrToInt64ExW() fail
            }
            WCHAR *p = time + leading_zeros, *q = time + leading_zeros;
            while (WCHAR c = *q++) if (c >= L'0' && c <= L'9') *p++ = c;
            *(p - leading_zeros) = L'\0'; // Truncate to 10th of seconds
            LARGE_INTEGER ds;
            ConPrint(!StrToInt64ExW(time, STIF_DEFAULT, &ds.QuadPart) || ds.HighPart != 0 ?
                "Elapsed:  ?\r\n" : Format(bufFormatMain,
                "Elapsed:  %8u %02u:%02u:%02u.%u\r\n"   // DDD HH:MM:SS.F
                                "%21u:%02u:%02u.%u\r\n"   //    HHH:MM:SS.F
                                    "%24u:%02u.%u\r\n"   //       MMM:SS.F
                                        "%27u.%u\r\n",  //          SSS.F
                ds.LowPart / 864000U,   ds.LowPart / 36000U % 24U,  ds.LowPart / 600U % 60U,    ds.LowPart / 10U % 60U, ds.LowPart % 10U,
                                        ds.LowPart / 36000U,        ds.LowPart / 600U % 60U,    ds.LowPart / 10U % 60U, ds.LowPart % 10U,
                                                                    ds.LowPart / 600U,          ds.LowPart / 10U % 60U, ds.LowPart % 10U,
                                                                                                ds.LowPart / 10U,       ds.LowPart % 10U),
                fLogFileQuiet);
        }
    }

Error:

    if( dwRetCode != ERROR_SUCCESS )
    {
        //
        // Print a nice, ugly, grepable error signature
        //
        if(!fLogFileQuiet)
            LogPrint(Format(bufFormatMain, "******ERROR executing %ls\r\n", pszArgs));
    }

    for( int i = 0; i < bufCount; i++ )
    {
        LocalFree(g_pszBuffer[i]);
    }

    LocalFree(pszChildCmdLine);

    if( hStdOutReadPipe != INVALID_HANDLE_VALUE )
        CloseHandle( hStdOutReadPipe );

    if( hStdOutReadPipeDup != INVALID_HANDLE_VALUE )
        CloseHandle( hStdOutReadPipeDup );

    if( hStdOutWritePipe != INVALID_HANDLE_VALUE )
        CloseHandle( hStdErrWritePipe );

    if( hStdErrReadPipe != INVALID_HANDLE_VALUE )
        CloseHandle( hStdErrReadPipe );

    if( hStdErrReadPipeDup != INVALID_HANDLE_VALUE )
        CloseHandle( hStdErrReadPipeDup );

    if( hStdErrWritePipe != INVALID_HANDLE_VALUE )
        CloseHandle( hStdErrWritePipe );

    if( hStdOutListenerThread != INVALID_HANDLE_VALUE )
        CloseHandle(hStdOutListenerThread);

    if( hStdErrListenerThread != INVALID_HANDLE_VALUE )
        CloseHandle(hStdErrListenerThread);

    if( g_hLogFileMutex != INVALID_HANDLE_VALUE )
        CloseHandle(g_hLogFileMutex);

    if( g_hLogFile != INVALID_HANDLE_VALUE )
        CloseHandle( g_hLogFile );

    if( ChildProcessInfo.hThread != INVALID_HANDLE_VALUE )
        CloseHandle(ChildProcessInfo.hThread);

    if( ChildProcessInfo.hProcess != INVALID_HANDLE_VALUE )
        CloseHandle(ChildProcessInfo.hProcess);

    ExitProcess(dwRetCode);
}
