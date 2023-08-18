---
title: "HUI Analysis"
date: 2023-08-13T18:04:47+05:30
---
## [1 Initial Analysis](#1-initial-analysis)

## [2 Secondary Analysis](#2-secondary-analysis)

    [2.1 Function 1](#21-function-1)

    [2.2 Function 2](#22-function-2)

    [2.3 Encryption](#23-encryption) 

    [2.4 cef_api_hash](#24-cef_api-_hash) 

    [2.5 Registry function](#25-registry-function)

## [3 Dynamic Analysis](#3-dynamic-analysis)

    [3.1 IDA Debugger](#31-ida-debugger)     

## [4 CAPA Analysis](#4-capa-analysis)

## [5 Conclusion](#5-conclusion)

# HUI Sample Analysis

Today, we will analyze a sample of HUI Loader and write a malware report on it

SHA256 - 3ad1a9770a533c2bb8be9d4e7150a2a167d0709c4b0339a5fd6a511008cea7ef

## Tools Used
Static Analysis: IDA,DIE,capa

Dynamic Analysis: - IDA Debugger, Regedit

## 1. Initial Analysis

For starters, Let us put it through DIE and see what comes up

{{< figure src="/die.png" caption="Fig 1.1 - DIE view" >}}

{{< figure src="/advanced.png" caption="Fig 1.2 - Advanced Options" >}}

From this, we can get that it is a 64 bit DLL and it's date stamp is
very recent

## 2. Secondary Analysis

Putting the binary into IDA, we can have a look at all the functions and API calls

{{< figure src="/2.1.png" caption="Fig 2.1 - Functions inside the binary" >}}

 bhui90=Binary seems to have a lot of functions but let us look at StartAddress first

StartAddress calls two functions

{{< figure src="/2.2.png" caption="Fig 2.2 - Functions present inside of StartAddress" >}}

### 2.1 Function 1

The first function is responsible for getting the handle for ntdll function and **dynamically** calling the APIs present inside of it as well as getting the process environment block of the current process using **NtCurrentPeb()** which basically has the same functionality of **NtCurrentTeb.**.
I'll name it Dynamic_Link for better understanding

{{< figure src="/2.1.1.png" caption="Fig 2.1.1 - sub_1800013F0" >}}


### 2.2 Function 2

The second one creates a file with filename **String1**, lets rename it
as File_name. Then, using **CreateFileMapping**, creates a mapping of the file which
basically means corresponding a portion of the file to a portion in the virtual address
space. After that, using **GetProcessHeap** and **HeapAlloc**, it allocates the shellcode
onto the heap which is then executed later via an indirect call, because we take the
handle to the Shellcode, give it read,write and execute permissions using
**VirtualProtect**, making it possible to just call it like a function. We will rename it to
File_Mapping. Inside this function, it calls another function as well.

Let us look into it 

{{< figure src="/2.2.1.png" caption="Fig 2.2.1 - sub_1800016E0" >}}

### 2.3 Encryption

Let us check out the function inside of sub_1800016E0, which could be
vital. Sub_180001820 seems like an encryption scheme. It has a lot of mod 256
fns. So this is most likely the RC4 encryption scheme.  We can confirm by
checking implementations online or if there is a consequent PRGA algorithm 

{{< figure src="/2.3.1.png" caption="Fig 2.3.1 - Encryption Fn" >}}

{{< figure src="/2.3.2.png" caption="Fig 2.3.2 - Reference" >}}

Searching online, I found this sample implementation. This looks just
like the basics of what is given inside of the function. So let us name
it RC4_Encryption.

### 2.4 cef\_api \_hash

The function cef_api_hash looks suspicious 

Looking inside we see a function call to sub_180001AA0

{{< figure src="/2.4.1.png" caption="Fig 2.4.1 - sub_180001AA0 disassembly" >}}

This function first used the api **GetModuleFileName** which retrieves
the full path of where  the file is present. If the handle is not
specified, then it takes the handle of the current process and proceeds
to get the file path. After a check , it renames the file to agent.data
which is  usually the payload name that HUI uses. This is done by using
the api call **lstrcat** which appends a string to another. Other APIs
being used are **CreateEvent** which for the time being creates a
nameless event without being signaled . But when we look at the
parameters, we see that the event reset has been set to 0, meaning after
the **WaitForSingleObject** function creating a waiting thread, it is
being set to non-signaled.  Also Thread creation is done using the
**CreateThread** API. As for the return value of CreateEvent, we should
take one thing into consideration - that **SetEvent** has already been
called in a previous function meaning this will set the event toa
signaled state. Let us rename this as Thread_creation.

### 2.5 Registry Function

After looking through a few more functions, we come across
cef_string_multimap_size, which uses **RegOpenKey** and **RegQueryInfoKey** which are registry
based APIs meaning, this function accesses the Windows Registries(".DEFAULT\\\\Software") and
gets information related to it too making it easy for the adversary to make required
changes to affect the System. **RegEnumKeyEx** iterates through the list of subkeys to
retrieve one single subkey which is being printed and finally closes it using **RegCloseKey.**

{{< figure src="/2.5.1.png" caption="Fig 2.5.1 - Registry based API calls" >}}

We will now check what exactly this function returns by using the **IDA debugger**

## 3. Dynamic Analysis

### 3.1 IDA Debugger

{{< figure src="/3.1.1.png" caption="Fig 3.1.1 - Debugging process setting" >}}

In the **cef_string_multimap_size**, set a couple breakpoints, set IP to
that function and start execution. Every time we run it, we get a new string inside of "name"

Let us note it down

    - Classes

    - Microsoft

    - Policies

    - Registered Applications

    - VMware .Inc litications.

Let us now open up regedit to check the registries and subkeys and we can see this.

{{< figure src="/3.1.2.png" caption="Fig 3.1.2 - Regedit Registry list" >}}

All of those are subkeys that come under **.DEFAULT/Software**. Each of those subkeys have classifications with different data values

## 4 CAPA Analysis
Capa is a tool that can be used to identify capabilities in executable files. It can be used to detect capabilities in malware samples. This is very helpful in our case as we can get a gist of what the malware is capable of doing

Let's check it out in **Capa**

{{< figure src="/4.1.png" caption="Fig 4.1 - Capa analysis" >}}

## 5 Conclusion
Based on static and dynamic analysis and the capa results, 
we can get the gist of how this malware functions. It first
contains encrypted payload i.e. shellcode which it decrypts and loads
onto the heap for dynamic execution. All of these are done using
different encryption schemes and malware techniques which I specified
above. 