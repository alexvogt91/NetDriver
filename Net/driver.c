#include <ntddk.h>
#include <tdi.h>
#include <tdikrnl.h>
#include <ntstrsafe.h>

/*/////////////////////////////////////////////
//
//	Description: Super basic TDI kernel-mode client
//		which can send and receive http requests
//
//	Contains basic routines & implementations for
//	such actions.
*//////////////////////////////////////////////



#define TCPDRIVER L"\\Device\\Tcp"
#define UDPDRIVER L"\\Device\\Udp"


UNICODE_STRING tcpip = RTL_CONSTANT_STRING(TCPDRIVER);
UNICODE_STRING udpdriver = RTL_CONSTANT_STRING(UDPDRIVER);
#define HTONS(a) (((0xFF&a)<<8) + ((0xFF00&a)>>8))
#define INETADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))

#define _malloc(_s) ExAllocatePoolWithTag(NonPagedPool,_s,'AlO');
#define _free(_s) ExFreePoolWithTag(_s, 'AlO');

/*///////////////////////////////////
//
//	Function: TdiCompletionRoutine
//
//	Purpose: Callback for the IRP
//
//
*////////////////////////////////////

NTSTATUS TdiCompletionRoutine(IN PDEVICE_OBJECT Object, IN PIRP Irp, IN PVOID Context) 
{
	if (Context != NULL) 
	{
		KeSetEvent((PKEVENT)Context, 0, FALSE);
	}

	return STATUS_MORE_PROCESSING_REQUIRED;
}


VOID Unload(PDRIVER_OBJECT pdriverobject) 
{
	DbgPrint("NetDrv Unloaded");
}

/*///////////////////////////////////
//
//	Function: TDIKernelConnection
//
//	Purpose: Create Connection Object
//  to create socket in Association
//  with Address Object
//
//	Environment: Kernel Mode only
//
*////////////////////////////////////

NTSTATUS TDIKernelConnection(IN PHANDLE Handle, IN PFILE_OBJECT **ConnectionObject) 
{
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	OBJECT_ATTRIBUTES oa;
	ULONG ubuffer;
	IO_STATUS_BLOCK io;
	CHAR EA_Buffer[sizeof(FILE_FULL_EA_INFORMATION) + sizeof(TdiTransportAddress)-1 + sizeof(TA_IP_ADDRESS)];
	PFILE_FULL_EA_INFORMATION	pEA_Buffer = (PFILE_FULL_EA_INFORMATION)EA_Buffer;
	CONNECTION_CONTEXT			contextplaceholder = NULL;
	
	ubuffer = FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) + sizeof(TdiConnectionContext)-1 + 1 + sizeof(CONNECTION_CONTEXT);
	pEA_Buffer = (PFILE_FULL_EA_INFORMATION)ExAllocatePool(NonPagedPool, ubuffer);
	if (pEA_Buffer == NULL) 
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlSecureZeroMemory(pEA_Buffer, ubuffer);
	pEA_Buffer->NextEntryOffset = 0;
	pEA_Buffer->Flags = 0;
	pEA_Buffer->EaNameLength = sizeof(TdiConnectionContext) - 1;
	RtlCopyMemory(pEA_Buffer->EaName, TdiConnectionContext, pEA_Buffer->EaNameLength + 1);

	pEA_Buffer->EaValueLength = sizeof(CONNECTION_CONTEXT);
	*(CONNECTION_CONTEXT*)(pEA_Buffer->EaName + (pEA_Buffer->EaNameLength + 1)) = (CONNECTION_CONTEXT)contextplaceholder;

	InitializeObjectAttributes(&oa, &tcpip, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	st = ZwCreateFile(Handle,FILE_GENERIC_READ |FILE_GENERIC_WRITE |SYNCHRONIZE,&oa,&io,0,FILE_ATTRIBUTE_NORMAL,FILE_SHARE_READ,FILE_OPEN,0,pEA_Buffer,sizeof(EA_Buffer));
	if (NT_SUCCESS(st))
	{
		st = ObReferenceObjectByHandle(*Handle,FILE_GENERIC_READ,NULL,KernelMode,(PVOID*)*ConnectionObject,NULL);
		if (NT_SUCCESS(st))
		{
			st = STATUS_SUCCESS;
		}
	}

	return st;
}

/*///////////////////////////////////////////////
//
//	Function: TDIKernelOpenAddress
//
//	Purpose: Create Address Object
//  to create socket in Association
//  with Connection Object
//
//	Environment:
//			Kernel mode only
//			
*/////////////////////////////////////////////////

NTSTATUS TDIKernelOpenAddress(IN PHANDLE *Handle, IN PFILE_OBJECT *ConnectionAddress, IN ULONG Ip, IN USHORT Port) 
{
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	OBJECT_ATTRIBUTES TDIObjectAttributes = { 0 };
	IO_STATUS_BLOCK io;
	PTA_IP_ADDRESS ipaddress;
	CHAR EABuffer[sizeof(FILE_FULL_EA_INFORMATION) + sizeof(TdiTransportAddress)-1 + sizeof(TA_IP_ADDRESS)];	// Fill the Extended Attributes Buffer
	PFILE_FULL_EA_INFORMATION pEABuffer = (PFILE_FULL_EA_INFORMATION)EABuffer;								// Define the pointer


	InitializeObjectAttributes(&TDIObjectAttributes, &tcpip, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	pEABuffer->NextEntryOffset = 0;
	pEABuffer->Flags = 0;
	pEABuffer->EaNameLength = sizeof(TdiTransportAddress) - 1;
	RtlCopyMemory(pEABuffer->EaName, TdiTransportAddress, pEABuffer->EaNameLength + 1);

	pEABuffer->EaValueLength = sizeof(TA_IP_ADDRESS);

	ipaddress = (PTA_IP_ADDRESS)(pEABuffer->EaName + pEABuffer->EaNameLength + 1);
	ipaddress->TAAddressCount = 1;																// Number of Addresses, only one
	ipaddress->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;								// length
	ipaddress->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;									// type of address
	ipaddress->Address[0].Address[0].sin_port = Port;											// define 0 for both port and Ip address
	ipaddress->Address[0].Address[0].in_addr = Ip;

	RtlSecureZeroMemory(ipaddress->Address[0].Address[0].sin_zero, sizeof(ipaddress->Address[0].Address[0].sin_zero));

	st = ZwCreateFile(*Handle, FILE_GENERIC_READ | FILE_GENERIC_WRITE | SYNCHRONIZE, &TDIObjectAttributes, &io, 0, FILE_ATTRIBUTE_NORMAL,FILE_SHARE_READ,FILE_OPEN,0, pEABuffer, sizeof(EABuffer));
	if (NT_SUCCESS(st))
	{

		st = ObReferenceObjectByHandle(**Handle, FILE_ANY_ACCESS, 0,KernelMode,(PVOID*)ConnectionAddress,NULL);
		if (NT_SUCCESS(st))
		{
			st = STATUS_SUCCESS;

		}

	}

	return st;
}

/*/////////////////////////////////////////
//
//	Function: TDIKernelCreateTCPSocket
//
//	Purpose: Create socket by associating
//    both the address object and the
//	  connection object.
//
//	Environment: Kernel mode only
//
*/////////////////////////////////////////

NTSTATUS TDIKernelCreateTCPSocket(IN PHANDLE AddressHandle, IN PFILE_OBJECT *ConnectionObject, IN PDEVICE_OBJECT *SocketObject) 
{
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	HANDLE objecthandle;
	KEVENT Event;
	PIRP Irp;
	PFILE_OBJECT AddressObject;
	IO_STATUS_BLOCK io;

	st = TDIKernelOpenAddress(&AddressHandle, &AddressObject, 0, 0);
	if (NT_SUCCESS(st))
	{

		st = TDIKernelConnection(&objecthandle, &ConnectionObject);
		if (NT_SUCCESS(st))
		{

			*SocketObject = IoGetRelatedDeviceObject(AddressObject);
			if (*SocketObject && MmIsAddressValid(*SocketObject))
			{
				KeInitializeEvent(&Event, NotificationEvent, FALSE);
				Irp = TdiBuildInternalDeviceControlIrp(TDI_ASSOCIATE_ADDRESS, *SocketObject, *ConnectionObject, &Event, &io);
				if (Irp)
				{
					
					TdiBuildAssociateAddress(Irp, *SocketObject, *ConnectionObject, NULL, NULL, *AddressHandle);
					IoSetCompletionRoutine(Irp, TdiCompletionRoutine, &Event, TRUE, TRUE, TRUE);

					st = IofCallDriver(*SocketObject, Irp);
					if (st == STATUS_PENDING)
					{
						KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
					}
					else
					{
						st = STATUS_SUCCESS;
					}
				}
				else
				{
					return STATUS_INSUFFICIENT_RESOURCES;
				}
			}
		}
	}

	return st;
}

/*/////////////////////////////////////////
//
//	Function: TDIKernelConnect
//
//	Purpose: Connects to existing
//    socket.
//	 Emulates connect function from winsock
//
//	Environment: Kernel mode only
//
*/////////////////////////////////////////

NTSTATUS TDIKernelConnect(IN PFILE_OBJECT *ConnectionObject, IN PDEVICE_OBJECT *DeviceObject, IN USHORT PortNumber, IN ULONG Firstoctal, IN ULONG Secondoctal, IN ULONG Thirdoctal, IN ULONG Lastoctal) 
{
	NTSTATUS st;
	PIRP Irp;
	TA_IP_ADDRESS ipaddress;
	USHORT Port;
	ULONG Ip;
	KEVENT Event;
	IO_STATUS_BLOCK io;
	TDI_CONNECTION_INFORMATION connectinfo;

	KeInitializeEvent(&Event, NotificationEvent, FALSE);

	Irp = TdiBuildInternalDeviceControlIrp(TDI_CONNECT, *DeviceObject, *ConnectionObject, &Event, &io);
	if (Irp == NULL) 
	{
		
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	Port = HTONS(PortNumber);
	Ip = INETADDR(Firstoctal, Secondoctal, Thirdoctal, Lastoctal);

	ipaddress.TAAddressCount = 1;
	ipaddress.Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
	ipaddress.Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
	ipaddress.Address[0].Address[0].sin_port = Port;
	ipaddress.Address[0].Address[0].in_addr = Ip;

	connectinfo.UserDataLength = 0;
	connectinfo.UserData = 0;
	connectinfo.OptionsLength = 0;
	connectinfo.Options = 0;
	connectinfo.RemoteAddressLength = sizeof(ipaddress);
	connectinfo.RemoteAddress = &ipaddress;

	TdiBuildConnect(Irp, *DeviceObject, *ConnectionObject, NULL, NULL, NULL, &connectinfo, 0);

	IoSetCompletionRoutine(Irp, TdiCompletionRoutine, &Event, TRUE, TRUE, TRUE);

	st = IofCallDriver(*DeviceObject, Irp);
	if (st == STATUS_PENDING)
	{
		KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, 0);
	}

	return st;

}

/*/////////////////////////////////////////
//
//	Function: TDISend
//
//	Purpose: Sends data to remote server
//    
//	 Emulates send function from winsock
//
//	Environment: Kernel mode only
//
*/////////////////////////////////////////

NTSTATUS TDISend(IN PFILE_OBJECT ConnectionObject, IN PDEVICE_OBJECT DeviceObject, IN PCHAR Data, IN ULONG Length)
{
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	KEVENT Event;
	PIRP Irp;
	PMDL Mdl;
	PCHAR Buffer = NULL;
	IO_STATUS_BLOCK io;

	Buffer = ExAllocatePool(NonPagedPool, Length);
	RtlCopyMemory(Buffer, Data, Length);

	KeInitializeEvent(&Event, NotificationEvent, FALSE);
	
	Irp = TdiBuildInternalDeviceControlIrp(TDI_SEND, DeviceObject, ConnectionObject, &Event, &io);
	if (Irp)
	{
		Mdl = IoAllocateMdl(Buffer, Length, FALSE, FALSE, Irp);
		if (Mdl)
		{
			__try
			{
				MmProbeAndLockPages(Mdl, KernelMode, IoModifyAccess);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return STATUS_UNSUCCESSFUL;
			}

			TdiBuildSend(Irp, DeviceObject, ConnectionObject, NULL, NULL, Mdl, 0, Length);

			IoSetCompletionRoutine(Irp, TdiCompletionRoutine, &Event, TRUE, TRUE, TRUE);

			st = IofCallDriver(DeviceObject, Irp);
			if (st == STATUS_PENDING)
			{
				KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
			}
			else
			{
				st = STATUS_SUCCESS;
			}

		}
		else
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	}
	else
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	return st;
}

/*/////////////////////////////////////////
//
//	Function: TDIRecv
//
//	Purpose: Receives data from remote server
//    
//	 Emulates recv function from winsock
//
//	Environment: Kernel mode only
//
*/////////////////////////////////////////

NTSTATUS TDIRecv(IN PFILE_OBJECT ConnectionObject, IN PDEVICE_OBJECT DeviceObject, PCHAR Data, ULONG Length)
{
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	PIRP Irp;
	KEVENT Event;
	IO_STATUS_BLOCK io;
	PMDL Mdl;

	KeInitializeEvent(&Event, NotificationEvent, FALSE);

	Irp = TdiBuildInternalDeviceControlIrp(TDI_RECEIVE, DeviceObject, ConnectionObject,&Event, &io);
	if (Irp)
	{
		Mdl = IoAllocateMdl(Data, Length, FALSE, FALSE, Irp);
		if (Mdl)
		{
			__try
			{
				MmProbeAndLockPages(Mdl, KernelMode, IoModifyAccess);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
				st = STATUS_UNSUCCESSFUL;
			}

			TdiBuildReceive(Irp, DeviceObject, ConnectionObject, NULL, NULL, Mdl, TDI_RECEIVE_NORMAL, Length);

			IoSetCompletionRoutine(Irp, TdiCompletionRoutine, &Event, TRUE, TRUE, TRUE);

			st = IofCallDriver(DeviceObject, Irp);
			if (st == STATUS_PENDING)
			{
				KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
			}
			else
			{
				st = STATUS_SUCCESS;
			}

		}
		else
		{
			st = STATUS_INSUFFICIENT_POWER;
		}
	}
	else
	{
		st = STATUS_INSUFFICIENT_RESOURCES;
	}

	return st;

}

/*/////////////////////////////////////////
//
//	Function: TDICloseSocket
//
//	Purpose: Closes existing ConnectionObject
//    
//	 Emulates closesocket function from winsock
//
//	Environment: Kernel mode only
//
*/////////////////////////////////////////

NTSTATUS TDICloseSocket(IN PFILE_OBJECT ConnectionObject, IN PDEVICE_OBJECT DeviceObject)
{
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	PIRP Irp;
	IO_STATUS_BLOCK io;
	KEVENT Event;

	KeInitializeEvent(&Event, NotificationEvent, FALSE);

	Irp = TdiBuildInternalDeviceControlIrp(TDI_DISCONNECT, DeviceObject, ConnectionObject, &Event, &io);
	if (Irp)
	{
		TdiBuildDisconnect(Irp, DeviceObject, ConnectionObject, NULL, NULL, NULL, TDI_DISCONNECT_RELEASE, 0, 0);

		IoSetCompletionRoutine(Irp, TdiCompletionRoutine, &Event, TRUE, TRUE, TRUE);

		st = IofCallDriver(DeviceObject, Irp);
		if (st == STATUS_PENDING)
		{
			KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
		}
		else
		{
			st = STATUS_SUCCESS;
		}
	}
	else
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	return st;
}



NTSTATUS DriverEntry(PDRIVER_OBJECT pdriverobject, PUNICODE_STRING RegisterPath) 
{
	
	DbgPrint("NetDrv Loaded");

	char recvrequest[1024] = { 0 };
	int size = 0;
	HANDLE AddressHandle = 0;
	PDEVICE_OBJECT DeviceObject = NULL;
	PFILE_OBJECT FileObject = NULL;
	NTSTATUS st;

	CHAR szHeader[] =
		"POST /panel/client.php HTTP/1.0\r\n"
		"Host: 192.168.1.33\r\n"
		"Content-Type: application/octet-stream\r\n"
		"Content-Encoding: binary\r\n"
		"Content-Length: 27\r\n"
		"Connection: close\r\n"
		"\r\n";

	char postreq[] = "name=kernelmode&password=tdi";
	int datalen = strlen(postreq);
	char header[sizeof(szHeader) + 100];

	RtlStringCchCopyA(header,sizeof(header), szHeader);
	int headerlen = strlen(header);

	// TDIKernelCreateTCPSocket acts like WSAStartup from winsock

	st = TDIKernelCreateTCPSocket(&AddressHandle, &FileObject, &DeviceObject);
	if (!NT_SUCCESS(st))
	{
		return STATUS_UNSUCCESSFUL;
	}

	// Connect to the remote server given 4 octal numbers and port number

	st = TDIKernelConnect(&FileObject, &DeviceObject, 80, 192, 168, 1, 33);
	if (!NT_SUCCESS(st))
	{
		return STATUS_UNSUCCESSFUL;
	}

	// send POST Request to the php panel

	st = TDISend(FileObject, DeviceObject, header, headerlen);
	if (!NT_SUCCESS(st))
	{
		return STATUS_UNSUCCESSFUL;
	}

	// send data

	st = TDISend(FileObject, DeviceObject, postreq, datalen);
	if (!NT_SUCCESS(st))
	{
		return STATUS_UNSUCCESSFUL;
	}

	// Receive HTTP request, response from the server

	st = TDIRecv(FileObject, DeviceObject, recvrequest, sizeof(recvrequest));
	if (!NT_SUCCESS(st))
	{
		return STATUS_UNSUCCESSFUL;
	}

	// null terminate the string

	recvrequest[strlen(recvrequest)] = '\0';
	DbgPrint("%s", recvrequest);

	// close socket
	// close AddressHandle
	// Decrement Object, we dont need it anymore

	TDICloseSocket(FileObject, DeviceObject);
	ZwClose(AddressHandle);
	ObfDereferenceObject(FileObject);


	pdriverobject->DriverUnload = Unload;

	
	return STATUS_SUCCESS;

}