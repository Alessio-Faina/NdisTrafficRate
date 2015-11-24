// NdisTrafficRate.cpp : Defines the entry point for the console application.
// Copyright (c) 2015 Alessio Faina
// Environment: user-mode

//TODO: a lot of error checking, but for now it's fine
//TODO: implement CSV output
//TODO: handle ctrl-c in device choose

#include <tchar.h>
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strsafe.h>
#include <ntddndis.h>
#include <ndisguid.h>

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

LPTSTR gDeviceIds[256];
LPTSTR gNames[256];
int gDiscoveredDevices = 0;
int gStopProgram = 0;

void 
FillValue(HKEY hKey, STRSAFE_LPCWSTR subKeyString)
{
	gNames[gDiscoveredDevices] = (LPTSTR)malloc(256);

	DWORD dwBufferSize = 256;
	int result = RegQueryValueExW(hKey, L"Name", 0, NULL, (LPBYTE)gNames[gDiscoveredDevices], &dwBufferSize);

	if (result)
	{
		free(gNames[gDiscoveredDevices]);
	}
	else
	{
		int startIndex = 0, endIndex = 0;
		int i = 0;
		int len = lstrlen(subKeyString);

		gDeviceIds[gDiscoveredDevices] = (LPTSTR)malloc(MAX_PATH * 2);

		for (; len > 0; len--)
		{
			if ((subKeyString[len] == '}') && (endIndex == 0))
			{
				endIndex = len;
			}
			if ((subKeyString[len] == '{') && (startIndex == 0) && (endIndex != 0))
			{
				startIndex = len;
				break;
			}
		}

		if ((startIndex != 0) && (endIndex != 0))
		{
			StringCchCopy(gDeviceIds[gDiscoveredDevices], 6, L"\\\\.\\");
			StringCchCat(gDeviceIds[gDiscoveredDevices], (endIndex - startIndex + 6), (subKeyString + startIndex));
		}

		gDiscoveredDevices++;
	}	
}

void 
ReadSubKey(HKEY hKey, STRSAFE_LPCWSTR subKeyString, int recursionLevel)
{
	TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
	DWORD    cbName;                   // size of name string 
	TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name 
	DWORD    cchClassName = MAX_PATH;  // size of class string 
	DWORD    cSubKeys = 0;               // number of subkeys 
	DWORD    cbMaxSubKey;              // longest subkey size 
	DWORD    cchMaxClass;              // longest class string 
	DWORD    cValues;              // number of values for key 
	DWORD    cchMaxValue;          // longest value name 
	DWORD    cbMaxValueData;       // longest value data 
	DWORD    cbSecurityDescriptor; // size of security descriptor 
	FILETIME ftLastWriteTime;      // last write time 
	DWORD i, retCode;

	if (recursionLevel == 3)
	{
		FillValue(hKey, subKeyString);
	}

	retCode = RegQueryInfoKey(
		hKey,                    // key handle 
		achClass,                // buffer for class name 
		&cchClassName,           // size of class string 
		NULL,                    // reserved 
		&cSubKeys,               // number of subkeys 
		&cbMaxSubKey,            // longest subkey size 
		&cchMaxClass,            // longest class string 
		&cValues,                // number of values for this key 
		&cchMaxValue,            // longest value name 
		&cbMaxValueData,         // longest value data 
		&cbSecurityDescriptor,   // security descriptor 
		&ftLastWriteTime);

	if (cSubKeys)
	{
		for (i = 0; i<cSubKeys; i++)
		{
			cbName = MAX_KEY_LENGTH;
			retCode = RegEnumKeyEx(hKey, i,
				achKey,
				&cbName,
				NULL,
				NULL,
				NULL,
				&ftLastWriteTime);
			if (retCode == ERROR_SUCCESS)
			{
				int recLev = recursionLevel;
				//TODO: Try to get a better way to differentiate the key
				if (((recursionLevel < 2) && achKey[0] == '{') || ((recursionLevel > 1) && (achKey[0] == 'C') && (achKey[1] == 'o')))
				{
					LPTSTR lpEnd;
					lpEnd = (LPTSTR)malloc(MAX_PATH * 2);
					HKEY subKey;

					StringCchCopy(lpEnd, MAX_PATH * 2, subKeyString);
					StringCchCat(lpEnd, MAX_PATH * 2, L"\\");
					StringCchCat(lpEnd, MAX_PATH * 2, achKey);

					int result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, lpEnd, 0, KEY_READ, &subKey);
					if (!result)
					{
						ReadSubKey(subKey, lpEnd, recursionLevel + 1);
						RegCloseKey(subKey);
					}
				}
			}
		}
	}
}

int 
GetInterfacesFromRegistry()
{
	HKEY hKey;
	HLOCAL mem = LocalAlloc(LPTR, 260);

	int result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Network", 0, KEY_READ, &hKey);
	if (result)
	{
		printf("Error %d", result);
	}
	else
	{
		ReadSubKey(hKey, L"SYSTEM\\CurrentControlSet\\Control\\Network", 0);
		RegCloseKey(hKey);
	}

	LocalFree(mem);
	return 0;
}

int 
SelectDeviceToUse()
{
	int i = 0;
	char buffer[4];
	int len = 0;
	printf("Available devices: \n");
	for (i = 0; i < gDiscoveredDevices; i++)
	{
		printf("(%i) - %ls\n", i, (const char *)gNames[i]);
	}
	printf("\n(Q) - Exit program\n");
	i = 0;
	while ((i == 0) || i>gDiscoveredDevices)
	{
		if (gStopProgram)
			return -1;
		printf("\nChoose a device: ");
		fgets(buffer, 4, stdin);
		len = strlen(buffer) - 1;
		i = atoi(buffer);		
		if (buffer[0] == 'q' || buffer[0] == 'Q');
		return -1;
	}
	return i;
}

void 
freeDevicesMemory()
{
	int i = 0;
	for (i = 0; i < gDiscoveredDevices; i++)
	{
		free(gNames[i]);
		free(gDeviceIds[i]);
	}
}

void 
freeMemory(PVOID dataXmit, PVOID dataRecv, HANDLE hDevice, PVOID dataXmitPacks, PVOID dataRecvPacks)
{
	freeDevicesMemory();
	if (dataXmit != NULL)
	{
		free(dataXmit);
	}
	if (dataRecv != NULL)
	{
		free(dataRecv);
	}
	if (dataXmitPacks != NULL)
	{
		free(dataXmitPacks);
	}
	if (dataRecvPacks != NULL)
	{
		free(dataRecvPacks);
	}
	if (hDevice != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hDevice);
	}
}

BOOL WINAPI 
consoleHandler(DWORD signal) {

	if (signal == CTRL_C_EVENT)
	{
		printf("Closing program......");
		gStopProgram = 1;
	}
	return TRUE;
}

void MainLoop(HANDLE hDevice)
{
	PVOID dataXmit;
	PVOID dataRecv;
	PVOID dataXmitPacks;
	PVOID dataRecvPacks;
	DWORD returned = 0;
	DWORD oidXmit = OID_GEN_DIRECTED_BYTES_XMIT;
	DWORD oidRecv = OID_GEN_DIRECTED_BYTES_RCV;
	DWORD oidXmitPacks = OID_GEN_DIRECTED_FRAMES_XMIT;
	DWORD oidRecvPacks = OID_GEN_DIRECTED_FRAMES_RCV;

	dataXmit = malloc(sizeof(ULONG64));
	dataRecv = malloc(sizeof(ULONG64));
	dataXmitPacks = malloc(sizeof(ULONG64));
	dataRecvPacks = malloc(sizeof(ULONG64));

	int currMs = 0;

	if (!DeviceIoControl(hDevice, IOCTL_NDIS_QUERY_GLOBAL_STATS, &oidXmit, sizeof(oidXmit), dataXmit, sizeof(ULONG64), &returned, NULL)) {
		DWORD err = GetLastError();
		printf("Error: %i", err);
		return;
	}
	else{
		SYSTEMTIME st;
		printf("              Timestamp,        BytesRX,        BytesTX,      PacketsRx,      PacketsTX,\n");
		while (!gStopProgram)
		{
			GetSystemTime(&st);
			DeviceIoControl(hDevice, IOCTL_NDIS_QUERY_GLOBAL_STATS, &oidXmit, sizeof(oidXmit), dataXmit, sizeof(ULONG64), &returned, NULL);
			DeviceIoControl(hDevice, IOCTL_NDIS_QUERY_GLOBAL_STATS, &oidRecv, sizeof(oidRecv), dataRecv, sizeof(ULONG64), &returned, NULL);
			DeviceIoControl(hDevice, IOCTL_NDIS_QUERY_GLOBAL_STATS, &oidXmitPacks, sizeof(oidXmitPacks), dataXmitPacks, sizeof(ULONG64), &returned, NULL);
			DeviceIoControl(hDevice, IOCTL_NDIS_QUERY_GLOBAL_STATS, &oidRecvPacks, sizeof(oidRecvPacks), dataRecvPacks, sizeof(ULONG64), &returned, NULL);
			printf(" %04d%02d%02d-%02d:%02d:%02d.%04d,%15llu,%15llu,%15llu,%15llu,\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
				(*(ULONG64*)dataXmit), (*(ULONG64*)dataRecv), (*(ULONG64*)dataXmitPacks), (*(ULONG64*)dataRecvPacks));
			currMs = st.wMilliseconds;
			Sleep(999 + (500-currMs));	  //try to be stable on the 500 ms reference point	
		}
	}
	freeMemory(dataXmit, dataRecv, hDevice, dataXmitPacks, dataRecvPacks);
}

int _tmain(int argc, _TCHAR* argv[])
{
	HANDLE hDevice;
	int errNum;

	if (!SetConsoleCtrlHandler(consoleHandler, TRUE)) {
		printf("\nERROR: Could not set control handler");
		return 1;
	}

	GetInterfacesFromRegistry();
	if (gDiscoveredDevices == 0)
	{
		printf("No available devices\n");
		return 0;
	}
	int deviceIndex = SelectDeviceToUse();
	if (deviceIndex == -1)
		return 0;

//		printf("for the device key: for example \n");
//		printf("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\{69110376-15D8-4833-BAFA-6C0A2EE47B09}\\Connection\\Name \n");
//		printf("is the Friendly interface name: what you must use is the second GUID {69110376-15D8-4833-BAFA-6C0A2EE47B09}  \n");
	
	if ((hDevice = CreateFileW(gDeviceIds[deviceIndex],
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL)) == INVALID_HANDLE_VALUE) {

		errNum = GetLastError();

		if (errNum == ERROR_FILE_NOT_FOUND) {
			printf("CreateFile failed!  ERROR_FILE_NOT_FOUND = %d\n", errNum);
			return -1;
		}
		else{
			printf("Can't find the interface! (%i)\n", errNum);
			return -1;
		}
	}

	MainLoop(hDevice);

	return 0;
}

