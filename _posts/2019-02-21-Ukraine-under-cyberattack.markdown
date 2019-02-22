---
layout: post
title:  "Ukraine under CyberAttack!"
date:   2019-02-21 12:17:52 +0100
categories: malwa-re
---
<p style="margin-top:50px;color:red">
New cyber attack on the business of Ukraine. Full analysis of the latest version of SmokeBot Loader
</p>

<a href="#intro">1. Introduction</a><br />
<a href="#tech">2. Infection technique</a><br />
<a href="#sandbox">3. Sandbox / online checkers</a><br />
<a href="#one">4. Part 1. removing the envelope (cryptor)</a><br />
<a href="#two">5. Part 2. jmp,jz/jnz obfuscation</a><br />
<a href="#explorer">6. Part 3. Under the wing of the explorer.exe</a><br />
<a href="#botnet">7. BotNet</a><br />
<a href="#plugins">8. Plugins</a><br />
<a href="#conclusion">9. Conclusion</a><br />



<p class="p_title">Introduction<a name="intro"></a></p>

In the end of January 2019, I received a new malware for analysis and  would like 
to tell more details about this malware.
After conducting a full analysis, it turned out that this is one of the latest 
versions of the SmokeBot Loader.
Further in the analysis I will show how the malware checks virtual environments, 
how work its numerous methods of survival in the wild, that malware needs 
for a long lifetime on users computers.

In the title of this analysis, I described an attack on the business of Ukraine 
and in the report I will demonstrate specific facts, that will prove this and I hope you 
will agree with my opinion.


<p class="p_title">Infection technique<a name="tech"></a></p>
<p class="p_space">
In my case, the sample was received by the scheme through the mailing list by e-mail. 
The scheme of such a "delivery of malware to the client" is quite run-in and 
popular among cyber criminals. First, an e-mail comes with a malicious 
attachment - a document .doc, obfuscated javascript, etc., which, as in our case, 
downloads a "loader" from a hacked site when launched. Next, the loader is 
installed in the system and, depending on its settings can perform various 
tasks, including downloading and launching other malware from the command center.
</p>

<p class="p_title">
Sandbox / online checkers<a name="sandbox"></a></p>

<p class="p_space">
Analysis of malware on analysis services (including services like 
virustotal.com) showed that this malware is identified by various antivirus 
programs as various types of malware (from ransomware to viruses), but any of
antivirus product identified it 100% . Analysis in virtual machines / sandboxes 
showed no activity. This indicates that the malicious code has methods for 
detecting virtual environments and blocking its dark work in a 
virtual environment.
</p>


<p class="p_space">
Our sample:
</p>

<pre style="margin-top:30px">
liter.exe
MD5 (liter.exe) = dbba4d0f4aa3fd7ab63fd2cb3889ae57
Size = 209920 Byte
</pre>

<p style="margin-top:50px"></p>
Let's Go...
<p class="p_title">
Part one - removing the envelope (cryptor)<a name="one"></a>
</p>

<p style="margin-top:30px">
The cryptor encrypts the main loader code in two steps.
At the beginning of the cryptor there are garbage commands that repeat 
many times in the cycle to stop the work of emulators.
</p>
<img class="code_image" src="/assets/images/pic1-garbage-cycle.png"/>
Also for loading of libraries (example kernel32.dll) dynamically generated lines are used instead of static, thereby bypass the static analysis of lines

<img class="code_image" src="/assets/images/pic2-kernel32.png"/>

Further we smoothly approach the code of the first stage of decrypting the envelope

<img class="code_image" src="/assets/images/pic3-1stdecrypt.png"/>

the decryption algorithm is quite simple

<img class="code_image" src="/assets/images/pic4-algo1st.png"/>

and immediately proceed to the second stage of decryption. For the second stage, the authors chose the algorithm TEA with the key 128bit. The key for decryption is static and is in clear view in the data area

<img class="code_image" src="/assets/images/pic5-tea.png"/>
<img class="code_image" src="/assets/images/pic6-tea-key.png"/>

Next comes the control to the beginning of the decrypted code only.
where is getting through PEB addresses of kernel32.dll and getting addresses of various APIs that are needed for further work

<img class="code_image" src="/assets/images/pic7-getapi.png"/>

anti-debug functions are also present in the code

<img class="code_image" src="/assets/images/pic8-antidebug.png"/>

Next, the memory is allocated and the executable file is unpacked into it, which is present at the end of the decrypted block earlier
After unpacking, executable is copied to the liter.exe address space and the header is configured, the sections are loaded over the old ones, then the control goes to the new entry point is made - 402d03
At this stage, you can dump the executable and get a workable code without an envelope and load it into the disassembler for further study.

<img class="code_image" src="/assets/images/pic9-unpack3.png"/>

<p class="p_title">
Part 2. jmp,jz/jnz obfuscation<a name="two"></a>
</p>

We immediately get into the code, which is jmp obfuscated.
<img class="code_image" src="/assets/images/pix-start.png"/>


The task of deobfuscation is solved in different ways, from writing scripts 
to writing tracers-analyzers of the utility of instructions in a particular block. 
If we look at this code closely, we can understand, that we are dealing with 
obfuscation of unconditional jmps and a pair of conditional jumps going one after 
the other to the same address jz, jnz (the same unconditional jump as a result). 
If you can view this code under the debugger and disassembler, you will not see difficulties with understanding the code;

so

At the beginning of the code there is a check for the OS version using Process Environment Block (PEB)
<img class="code_image" src="/assets/images/pix-os.png"/>

Further, through PEB, the presence of the debugger is checked and, if it exists, then the control goes to the incorrect address
<img class="code_image" src="/assets/images/pix-debug.png"/>


Smoke's further work is divided into logical blocks, each block contains a prologue and an epilogue. In the prologue, the block code is decrypted, then the control goes to the decrypted part of the block and in the epilogue again its encryption and the control to the next block. This gives Smokey all the time in memory to be encrypted and decrypted as needed. That works very well against those who want to take a dump and quickly see content.
Two methods are used to encrypt code and data, one is a single-byte key byte xor (004012F9) - used to encrypt / decrypt blocks of code, the other method is xor with dword key, used to decrypt data (004013CE)

<img class="code_image" src="/assets/images/pix_decrypt_byte.png"/>

Encryption / Decryption malware code with 1 byte key length

<img class="code_image" src="/assets/images/pix-decrypt_dd.png"/>
Encryption / Decryption malware code with 4 byte (dword) key length

The whole code is broken into about 20 blocks with a prolog-decryptor and an epilogue-cryptor

<pre>
function ZZZ
prolog 	     - decryptor (XXXXXXX)
XXXXXXXXX    - 
epilogue     - encryptor (XXXXXXX)
ret
</pre>

I wrote a small script that decrypts the blocks of code (XXXXX blocks) and data needed for the analysis, with the result of that you can safely analyze the code in IDA

{% highlight python %}

blocks = [
[0x00401400,0x50], [0x0040148C,0x9f], [0x00401565,0x8d], [0x00401629,0x4a],
[0x004016B0,0x1e9],[0x004018D6,0x28d],[0x00401BA3,0x1f5],[0x00401DD8,0x1e0],
[0x00401FF5,0x98], [0x004020CD,0x9c], [0x004021AC,0x1b3],[0x004023A0,0x119],
[0x004024F7,0x51], [0x00402586,0x91], [0x00402654,0x56], [0x004026E9,0x87],
[0x00402970,0x71], [0x0040279D,0xa2], [0x0040286C,0xd7]]


def xor_byte():
	for i in blocks:
		ea=i[0]
		for z in range(i[1]):
			b=Byte(ea+z)
			b^=0x2d
			PatchByte(ea+z,b)



block_data =[ [0x402d9f,0xd0], [0x401377, 0x57] ]

def xor_dd():
	for i in block_data:
		ea=i[0]
		bs=i[1] % 4
		for z in range(i[1]/4):
			d=Dword(ea)
			d^=0xDF9DA2D
			PatchDword (ea,d)
			ea+=4

		for q in range(bs):
			b=Byte(ea+q)
			b^=0x2d
			PatchByte(ea+q,b)


{% endhighlight %}


After checking for the presence of a debugger, a control goes to the code that decrypts the first data block to the address (402d9f)
<img class="code_image" src="/assets/images/pix-1st-data-dec.png"/>



This data block contains table of dword. Each dword  - hash(API function name) of various libraries, whose addresses are located through the 
export table of the corresponding library.
<img class="code_image" src="/assets/images/pix-data-hash.png"/>

To find the Native API, Smoke, through PEB, finds the address of the ntdll.dll module in memory, then through parsing the ntdll PE header, gets to the export table, which it passes through sequentially, calculating the hashes of all export names and comparing them with the hash that is in the decrypted block data. If found, the address is stored in a table for future use.
<img class="code_image" src="/assets/images/pix-api-export-by-hash.png"/>



In addition to ntdll, Smoke gets api from kernel32, user32, advapi32, shell32 by the same method, preloading them using api LdrLoadDll


Next, a checksum of a 402e6f block of 0x2c65 bytes size is checked. Checksum xor'ed with 69D99D17h (if all fine, result must be zero)
<img class="code_image" src="/assets/images/pix-crc-xor.png"/>

The result is added to the value of the esp register. Therefore, if the block is changed and the checksum does not match, the malware will not complete correctly after the first ret

Next, check for the presence of hooks and patches in the native api code. Thus various antivirus and monitoring software are in effect, and if there are any, then there will be no further cases.

<img class="code_image" src="/assets/images/pix-check_patch.png"/>



We got to the "delicious" topic, namely, checking the keyboard layouts installed in the system. Smokebot will work <b>ONLY</b>, if the Ukrainian layout is installed in the system, and if there is none, then the presence of Russian is checked. This is one of the factors in my approval of the attack on the Ukrainian business. You may reasonably notice about the Russian layout, BUT, this is not my only argument)) In any case, we understand which users in the world can be affected as much as possible by this attack. Also, such a test can discard various kinds of sandboxes in which there are no such layouts.

<img class="code_image" src="/assets/images/pix-keyboard.png"/>



Having touched on the subject of sandboxes and virtual machines, we just got to their checks) Verification consists of finding a module in the system and analyzing registry branches
<img class="code_image" src="/assets/images/pix-sandboxie.png"/>

Check on Sandboxie

<img class="code_image" src="/assets/images/pix-reg1.png"/>
<img class="code_image" src="/assets/images/pix-reg2.png"/>
<img class="code_image" src="/assets/images/pix-vm.png"/>

Check registry keys for the presence of keys with the words virtio, vmware, vbox, xen


Check the checksum of the 405ad4 block with the size of 398Dh according to the scheme described above. Checksum xored with 0A8923A34h
<img class="code_image" src="/assets/images/pix-crc2.png"/>

<img class="code_image" src="/assets/images/pix-token.png"/>

As well as checking the process rights, if they are not less than 0x2000 (Medium), otherwise it tries to start itself in a loop through runas
<img class="code_image" src="/assets/images/pix-runas.png"/>

where we run x64 or x86 system? Determined by the value of the GS segment register. Under x64 this register is not zero, in x86 the value is zero.
Depending on the register, this or that data block is selected, with which we will work further. These are exactly the blocks whose checksums were checked above.

<img class="code_image" src="/assets/images/pix-gs.png"/>


The selected block is decrypted by the algorithm for decrypt data, then a block of memory is allocated and the newly decrypted block is unpacked there via api RtlDecompressBuffer
<img class="code_image" src="/assets/images/pix_decompress.png"/>


Start of Inject decompressed code to explorer.exe

<img class="code_image" src="/assets/images/pix-inject.png"/>


Inject algorithm looks something like this

<pre>
1. GetShellWindow
2. GetWindowThreadProcessId
3. NtOpenProcess
4. NtCreateSection
5. NtMapViewOfSection - explorer
6. NtMapViewOfSection - my process
</pre>


<img class="code_image" src="/assets/images/pix-section.png"/>


The unpacked code is a trimmed and cleaned PE file, it contains part of the PE header (I’m going to restore such files later in this analysis, but this is not important now). Using this data, sections of PE are copied and configured in memory, relocs are configured and control pass directly to injection shellcode using new technic called PROPagate. Among all the сhild windows of the shellwindow, it looks for a UxSubclassInfo property.
If it is, Smoke create another section in the explorer and copy to it the shellcode with callback function for SetPropA
<img class="code_image" src="/assets/images/pix-propa.png"/>


callback function, create a thread, the start address of the thread is the entry point in the unpacked file.
<img class="code_image" src="/assets/images/pix-propcallback.png"/>

<p class="p_title">
Part 3. Under the wing of the explorer.exe<a name="explorer"></a>
</p>
<img class="code_image" src="/assets/images/bot-init.png"/>

This part of Smoke is devoid of any obfuscations and crypters
It starts with initialization, which receives the addresses ntdll and kernel32 via PEB.
Decrypts the list of dll that loads and then through the hash table
find out the addresses of a large number of apis
bot-hash
For normal analysis in statics, you need to restore all these api, so I wrote a small script that matches the api names of their hashes, thereby making the analysis comfortable

{% highlight python %}

import pefile
import idc


def get_functions(dll_path):
    pe = pefile.PE(dll_path)
    expname = []
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
      if exp.name:
        expname.append(exp.name)
    return expname

def rol(data, shift, size=32):
    shift %= size
    remains = data >> (size - shift)
    body = (data << shift) - (remains << size )
    return (body + remains)

def calc_hash(apiname):
    hash=0
    for iq in apiname:
      b = ord(iq) & 0xdf
      hash = hash ^ b
      hash = rol(hash,8,32)
      hash = hash + b
    
    hash = hash ^ 0x2714D596
        
    return hash
    

#ntdll=get_functions('ntdll.dll')
#eastart=0x3de1620
#eaend= 0x3de1660
#api_addr_start=0x3DE40A0

#ntdll=get_functions('kernel32.dll')
#eastart=0x3de1150
#eaend= 0x3de1230
#api_addr_start=0x3DE6e00

#ntdll=get_functions('user32.dll')
#eastart=0x3de12e0
#eaend= 0x3de12f4
#api_addr_start=0x3DE6dd0

#ntdll=get_functions('advapi32.dll')
#eastart=0x3de1270
#eaend= 0x3de12b0
#api_addr_start=0x3DE50f0

#ntdll=get_functions('ole32.dll')
#eastart=0x3de12b0
#eaend= 0x3de12c4
#api_addr_start=0x3DE6df0

ntdll=get_functions('winhttp.dll')
eastart=0x3de1230
eaend= 0x3de1260
api_addr_start=0x3DE5d30

#ntdll=get_functions('dnsapi.dll')
#eastart=0x3de1264
#eaend= 0x3de126c
#api_addr_start=0x3DE6d64


apiadd=api_addr_start-eastart

ea=eastart
while ea < eaend:
    h = Dword(ea)
    for i in ntdll:
        q=calc_hash(i)
        if (q == h):
            print hex(ea) + '  apiname: '+ i + '  hash: ' + hex(h)
            MakeDword(ea)
            MakeDword(ea+apiadd)
            idc.MakeNameEx(ea, i+'_hash', idc.SN_NOWARN)
            idc.MakeNameEx(ea+apiadd, i+'_addr', idc.SN_NOWARN)
            break
    ea+=4
    

{% endhighlight %}



Next Smoke creates two threads.
<img class="code_image" src="/assets/images/bot-thread.png"/>


The first thread goes through the list of running processes, and if the hash of process name ==  hash from the table, then process terminate. The second thread passes through all windows and if the hash from the name of the window class == hash from table one, then the process terminate.
I did not check the entire list, but ProcessHacker.exe is exactly on this list - it hash 0x5920de3d))

<img class="code_image" src="/assets/images/bot-killhash.png"/>


All text lines are located in one block which is encrypted (03DE1304h). The block looks like:
<pre>
length str0
str0
length str1
str1
....
</pre>

For encryption, the authors chose the RC4 algorithm and a 4-byte key.
To analyze this data, I wrote a script that decrypts it.
The key 27F9051Bh was chosen for encryption.

decrypted data is as follows

{% highlight python %}

num: 1  size: 32
http://www.msftncsi.com/ncsi.txt

num: 2  size: 36
Software\Microsoft\Internet Explorer

num: 3  size: 12
advapi32.dll

num: 4  size: 9
Location:

num: 5  size: 11
plugin_size

num: 6  size: 13
\explorer.exe

num: 7  size: 6
user32

num: 8  size: 7
shell32

num: 9  size: 8
advapi32

num: 10  size: 6
urlmon

num: 11  size: 5
ole32

num: 12  size: 7
winhttp

num: 13  size: 6
ws2_32

num: 14  size: 6
dnsapi

num: 15  size: 10
svcVersion

num: 16  size: 7
Version

num: 17  size: 53
S:(ML;;NW;;;LW)D:(A;;0x120083;;;WD)(A;;0x120083;;;AC)

num: 18  size: 12
%s\%hs

num: 19  size: 8
%s%s

num: 20  size: 28
regsvr32 /s %s

num: 21  size: 20
%s\%hs.lnk

num: 22  size: 54
%APPDATA%\Microsoft\Windows

num: 23  size: 12
%TEMP%

num: 24  size: 18
%ComSpec%

num: 25  size: 8
.exe

num: 26  size: 8
.dll

num: 27  size: 32
/c start "" "%s"

num: 28  size: 32
:Zone.Identifier

num: 29  size: 8
POST

num: 30  size: 94
Content-Type: application/x-www-form-urlencoded

num: 31  size: 10
runas

num: 32  size: 16
Host: %s

num: 33  size: 10
PT10M

num: 34  size: 38
1999-11-30T00:00:00

num: 35  size: 58
Opera scheduled Autoupdate %u

num: 36  size: 48
Accept: */*
Referer: %S

{% endhighlight %}

after the launch of the killer-thread, the Smoke goes into a loop that checks the internet connection and if it is not, then falls asleep for a certain time and tries to repeat the check again. In case of success, it make connection with the command center. For checking the network and communication to with CC, the Smoke uses the same function.

To check the connection, Smoke tries to load the page by number 1 from the encrypted block - http://www.msftncsi.com/ncsi.txt
<img class="code_image" src="/assets/images/bot-connect-check.png"/>


In case of success, Smoke forms a unique computer hash (BotId) consisting of the computer name and the serial number of the system disk.
<img class="code_image" src="/assets/images/bot-id.png"/>



then it is installed in the system, the new file name is generated based on the first 8 BotId symbols, which are mutated using a substitution algorithm.
<img class="code_image" src="/assets/images/bot-mutate.png"/>

Through SHGetFolderPathW, it receives the path to User startup directory and forms a string with the name of the link file for the user startup directory.
<img class="code_image" src="/assets/images/bot-startup.png"/>


Tries to expand the path %APPDATA%\Microsoft\Windows, if it does not work, then it expand %TEMP%, creates a directory named from BotId there
and copies the file from which it was launched, also under a new name and sets the hidden attribute. The file date and time is the same as file advapi32.dll. Removes the NTFS stream Zone.Identifier from the new file (which means that the file was downloaded from the Internet)
<img class="code_image" src="/assets/images/bot-settime.png"/>

Through the COM object, IShellLink creates a prepared lnk file.
<img class="code_image" src="/assets/images/bot-com.png"/>

And for launches a new file, Smoke through TaskSheduller creates a task in the scheduler with name 'Opera scheduled Autoupdate 1765637818', with property interval = 10 minutes (PT10M), 
<img class="code_image" src="/assets/images/bot-task.png"/>
<img class="code_image" src="/assets/images/bot-taskname.png"/>


In the process of installtion, the command center url is also decrypted and its crc32 is checked, if it has been modified, the process of system installation is interrupted.
<img class="code_image" src="/assets/images/bot-check_cc.png"/>

Also Smoke blocks deletion of a new file and link file by opening them with read permissions.

<img class="code_image" src="/assets/images/bot-fileblock.png"/>

<p class="p_title">
Part 7. Botnet. <a name="botnet"></a>
</p>

Smoke takes the current URL of the command center and decrypts it
<img class="code_image" src="/assets/images/bot-urldecrypt.png"/>

In my case, two command center addresses are used:
<pre>
http: //aviatorssm.bit/
http: //anotherblock.bit/
</pre>


Checks whether there is a plug-in file in the system (in the same folder as above), if it exists, then decrypt it with the rc4 algorithm and key BotId
<img class="code_image" src="/assets/images/bot-decplugin.png"/>
and reads the first 32 bytes - the hash of the plug-in, which is later used not to download plug-ins again

Generates a package to send to the server and sends it.

usually the packet is 63 bytes in size, if there is a plugin in the system, the packet size is increased by the size of the plug-in hash

<img class="code_image" src="/assets/images/bot-packet.png"/>

The package structure looks like this

<pre>
+0 dw 2018 (magic)
+2 - ascii bot id
+2b - ascii 6 byte array
+31 db OS dwMajorVersion << 4 + dwMinorVersion
+32 db Zero
+33 db proc rights 1 < 2000
+34 dw bot command (10001 - init, 10002 - get task, 10003 - confirmation)
+36 dd bot subcommand
+3a dd Installed in system (1)
+3e plugin hash
</pre>

let's look at the code that is responsible for working with the network (sending and receiving)

First of all, Smoke checks which domain the command center uses. If this is a .bit domain, then to resolve ip, a list of hardcoded dns-servers will be used, which respond to requests for resolving .bit domains
<img class="code_image" src="/assets/images/bot-checkbit.png"/>

Further work goes according to the following scenario.
checkproxy - Checks whether the proxy server address is set in the system and if so, saves it for work
winhttpopen
winhttpcrackurl
resolvebitdomain

If the bit is a domain, then this list of DNS servers is used for resolving
<img class="code_image" src="/assets/images/bot-dnslist.png"/>

and again small script
{% highlight python %}
import socket
import struct

dns = [0xD0F547C0, 0x6E79FB3A,
0xCD4FE265, 0x9CC8A5BC, 0xB1B179B9, 0x35B179B9, 0x26854C90,
0xCACAEFA9, 0x92B78705, 0x4262B7C1, 0x7319FE33, 0x4E30FF33]

for i in dns:
	print socket.inet_ntoa(struct.pack("<L", i))

192.71.245.208
58.251.121.110
101.226.79.205
188.165.200.156
185.121.177.177
185.121.177.53
144.76.133.38
169.239.202.202
5.135.183.146
193.183.98.66
51.254.25.115
51.255.48.78
{% endhighlight %}

Next, a POST-request to the server is formed with the following headers:
<pre>
"Content-type": "application / x-www-form-urlencoded",
"Accept": "* / *",
"Referer": "http: //aviatorssm.bit/",
"Host": "aviatorssm.bit"
</pre>

then the generated packet is encrypted using the rc4 algorithm with the key 4E29AB2Ch

and sent to the server
<img class="code_image" src="/assets/images/bot-senddata.png"/>


and receives data in response from the server

A received packet consists of blocks, at the beginning of a block there is a field of 4 bytes - this is the size of block, followed by data
The first block is decrypted by the rc4 algorithm and the key 693D7EBAh
<img class="code_image" src="/assets/images/bot-packet-decrypt.png"/>


the first block is text-block and carries commands from the server, settings for various plugins
At the beginning of this block, word magic should be - 2018, if everything is in order, then the plugin_size string is searched and its value is received. if everything is ok, the second block is encrypted with rc4 and the BotId key and saved to a file in the AppData\Roaming\Microsoft\Windows\xxxx\xxxx (xxxx - names that were previously generated) - plugin file. Later in the report we will examine this text header in detail.


further analysis of the command received from the server
Smoke supports the following commands:
<pre>
i, r, u
u - upgrade
r - remove
i - install file
or task number up to 100
</pre>

in my variant was task number 1. Then sequential loading of tasks takes place, the command 10002 is used for loading
<img class="code_image" src="/assets/images/bot-task_dl.png"/>


which are further decrypted by the same rc4 with the key 693D7EBAh stored in appdata and started
<img class="code_image" src="/assets/images/bot-runtask.png"/>


After this, control passes to the main loop, in which the plugins processing procedure begins
<img class="code_image" src="/assets/images/bot-main-cycle.png"/>

<p class="p_title">
Part 8. Plugins. <a name="plugins"></a>
</p>



First of all, the plugins file is readed from the disk (where it was previously saved) and decrypted by the rc4 algorithm with BotID key
<img class="code_image" src="/assets/images/bot-decrypt-plugins.png"/>

Let's talk more about plugins block. So... The block of plugins begins with a general header of all plugins, which contains information about what size of all plugins, plugins identifier = 0xF9B91548 and the number of plugins in the block. In my case, there are 11 plugins in the block. It is worth noting that some of them do not start because they have the Disabled attribute.


<pre>
Plugin Block Header
+0 dd size of all plugins
+4 dd magic (hardcoded in binary)
+0xc db plugins count in block
+0xd - First plugin in block
</pre>


After the general header there are plugins that also have their own header, which contains the size of the plugin and a 15-byte key for decryption algo RC4, in order to decode the plugin code


<pre>
Plugin 
 +0x0 Plugin Header
   +0 dd plugin size
   +4 db[0xf] - rc4key for plugin decrypt
 +0x15 Encrypted plugin code
</pre>

After the plugin is decrypted, an information block is created in the memory for the plugin, which is passed as a parameter when it is launched. This block contain  BotId, the url of the command center, the rc4 key for encryption, useragent string to connect and shellcode
<img class="code_image" src="/assets/images/plugin-inmem.png"/>
<img class="code_image" src="/assets/images/plugin-inmem2.png"/>

<img class="code_image" src="/assets/images/plugin-infoblock.png"/>

Plugins are launched by injecting into the process explorer.exe, which Smoke launches suspended. Then two sections are created in the process. The first one contains the information block and the shellcode for transferring control to the plugin entry point, the second one sets up the plugin code — code sections are created

<img class="code_image" src="/assets/images/plugin-shellcode.png"/>
<img class="code_image" src="/assets/images/plugin-shellcode_debug.png"/>

then at entrypoint of explorer.exe jump to shellcode is written and the process starts
<img class="code_image" src="/assets/images/plugin-jmp.png"/>

The analysis of the Smoke loader code itself can be completed and proceed to the analysis of plug-ins.

<p class="p_title">
Part 9. Plugin PE-reconstruction. <a name="restore"></a>
</p>


After analyzing the code for injecting the plugin, I saw that the decrypted plugin in memory is an executable file, with a partially overwritten PE header with zeros. The beginning of the plugin is the offset 0x3c of a regular PE file. On this offset is the field (in DOS Header) in which the PE Header offset is located. When I began to analyze the code of the injected plug-in in the debugger, I saw that its code was packed. Of course, for analysis you can make a memory dump and work with it - analyze packaging methods, see what the plugin code does. BUT we have 11 plugins, so I decided to take the path of restoring a workable PE file, which can be analyzed without problems in a disassembler. Script for the reconstruction of all plugins will also be attached in this report.


If you, like me, have been analyzing malware for more than one year, then you will be able to determine visually what kind of packer you have in front of your eyes, with a high probability, especially if this UPX packer :) or you can also use various packer detectors. 

Therefore, our task is to to restore the plugin header in such a way as to run upx -d and it could recognize the packaged file and unpack it.


I will not dive into the description of the PE file structure for this there is a lot of information on the Internet. I will only touch on the fields that we need to restore.

I will recover pe file in two stages, the first stage is the creation of a _minimal PE header_. With such a PE header, PE-editors should open this file  and understand that this is PE-File. The second stage is the recovery of data needed for the unpacker upx. which will be perceived by PE editors. The second stage is the recovery of data needed for the unpacker.


So

As I wrote above, the plugin code starts with DOS Header + 0x3c

Therefore, restore dos stub
<pre>
        stub[0:1]='MZ'
        stub[0x18]=0x40
		stub[0x3c]=first dd from plugin
</pre>


Next, go to the PE header
In the plugin, only part of the fields are not overwritten with zeros, let's consider them.
We have the following fields from the plugin
<pre>
Num of Sections,
SizeOfUninitializedData,
EntryPoint,
ImageBase,
Imagesize
and a partial section description
</pre>

image base, which in all plugins is 0x10000000, says as a rule that this is a dll file

So let's restore these PE header fields here.

<pre>
0x0 - PE sign
0x4 - CPU type - 0x14c - i386
0x14 - Size Of Optional Header
0x16 - Characteristics - 0x210e - dll with relocs
0x18 - Magic - 0x010b
0x38 - Section Alignment - 0x1000
0x3c - File Alignment - 0x200
0x54 - Header size - 0x400
0x74 - Number Of Rva And Sizes
</pre>

Already after these changes, the file can be opened in the peeditor and analyzed, but this data is not enough for UPX to consider that the file is correctly packed. To determine which fields still need to be recovered, I analyzed the source code of the UPX unpacker (<a href="https://github.com/upx/upx">https://github.com/upx/upx</a>) and determined what other data we need to recover. These are the names of the sections, which must contain 'UPX' and the upx header itself, which is necessary for the correct unpacking of the packed file.

<pre>
# recovery upx header sign + packer version (13)
0x3e0 - 'UPX!'+chr(13)
</pre>

Now the file can be unpacked and analyzed, but this no longer applies to this article. :)

{% highlight python %}
#!/usr/bin/python 
import sys
import os
from Crypto.Cipher import ARC4
import struct

class PluginUnpack(object):

    def __init__(self, filename, key):
        self.filename = filename
        self.key=key
        try:
            with open(self.filename, 'rb') as f:
                self.data=f.read()
                self.parse_file()
        except: 
                print "Error open file: " + self.filename
    		raise SystemExit(0)

#binary block struct
#+0 size1st dd - size of 1st part
#db[size] - encrypted 1st part. This is encrypted with rc4 key (key len = 4, hardcoded in binary) text part.
#db 0
# size1st+5 - here come plugins header (ph)
#+0 dd size of all plugins
#+4 dd magic (hardcoded in binary)
#...
#+0xc db plugins count
#ph+0xd - First plugin in block
#
# plugin block struc
# 0x15 bytes header
# +0 dd plugin size
# +4 db[0xf] - rc4key for plugin decrypt
# +0x15 - encrypted plugin 
#

    def parse_file(self):

	#get 1st text header from plugin
        self.text_header_size = struct.unpack("<I",self.data[0:4])[0]
        d=self.data[4:4+self.text_header_size]

        rc4 = ARC4.new(self.key)
        self.text_header= rc4.decrypt(d)
        del rc4


# get plugins header
        i=self.text_header_size+5
        self.plugins_size = struct.unpack("<I",self.data[i:i+4])[0]
        self.plugins_magic = struct.unpack("<I",self.data[i+4:i+4+4])[0]
        self.plugins_count=ord(self.data[i+0xc])
        self.plugins_offset = i+0xd

        i += 0xd
        self.plugins=[]
# decrypt all plugins
        while i < self.plugins_size:
            p_size = struct.unpack("<I",self.data[i:i+4])[0]
            buf0x15=self.data[i:i+0x15]
            p_rc4key = buf0x15[5:0x14]

            dec=self.data[i+0x15:i+0x15+p_size]  

            rc4 = ARC4.new(p_rc4key)
            decrypted_plugin = rc4.decrypt(dec)
            del rc4

            i+=p_size+0x15

            p_disabled = ord (decrypted_plugin[4])

            current_plugin = [p_size,p_rc4key,decrypted_plugin,p_disabled]
            self.plugins.append(current_plugin)


# plugin start from byte MZ + 0x3c. PE header filled with zeros. 
# Only few PE header params not deleted and they used for manual binary load 
# plugin is DLL format
# dll entrypoint have 3 params
# 1st - dll image base
# 2 - 1 (DLL_PROCESS_ATTACH)
# 3 - pointer to memory with bot_id, bot cc url, user agent string (363h header) and crypted plugin
# Plugin code (entrypoint)  
# plugin started in explorer.exe 
#with direct call dllentrypoint with pointer to memory block with bot data
# explorer entry point patched with e9 (jmp) to created memory block with shellcode, which make direct call
# in dllentrypoint i found unpacker. it looks like upx. so
# we can dump memory and make analys, but i try to rebuild destroyed headers and unpack clean plugin code, for static analyses
# 
# i traced upx with unpack params and checked what pe header fields need for correct unpack ;)
#
    def reconstruct_pe_header(self,num):
        plugin = self.plugins[num]
        # get decrypted plugin code
        b = bytearray(plugin[2]) 

# rebuild PE header        
        peh=struct.unpack("<L",b[0:4])[0]

#restore 'PE' header
        b[peh:peh+2]=b'PE'
#cpu type
        b[peh+4:peh+4+2]='\x4c\x01'
#optional header size + 18
        peh_size=0xe0
        b[peh+0x14]=peh_size


#dll, reloc - characteristics
        b[peh+0x16:peh+0x16+2]='\x0e\x21'
#pe magic
        b[peh+0x18:peh+0x18+2]='\x0b\x01'
#section aligment = 0x1000
        b[peh+0x39]=0x10
#file aligment = 0x200
        b[peh+0x3d]=2
#pe header size
        b[peh+0x55]=4
#objects num in dir
        b[peh+0x74]=0x10

# restore sections name 
        i=0
        while i<3:
            b[peh+peh_size+0x18+i*0x28:peh+peh_size+0x18+i*0x28+4]='UPX'+chr(i+0x30)
            i+=1

# recovery upx header sign + packer version (13)
        b[0x3e0:0x3e0+5]='UPX!'+chr(13)

#print '{:02x}'.format(peh)

# recovery dos stub
        stub=bytearray(peh-1)
        stub[0:1]='MZ'
        stub[0x18]=0x40
        stub[0x3c]=chr(peh)
        buf=stub + b[peh:]
        print chr(b[peh])

        return buf



if __name__ == '__main__':

    key = b'\xba\x7e\x3d\x69'
    pu=PluginUnpack("result",key)

    print pu.text_header

    print "Plugins size: " + str(pu.plugins_size)
    print "Plugins magic: " + hex(pu.plugins_magic)
    print "Plugins count: " + str(pu.plugins_count)
    i=0
    while i<pu.plugins_count:
        k=pu.plugins[i]
        print "\n\nPlugin N: " + str(i+1) + "  Disabled: " + str(k[3])
        print "\nPlugin size: " + str(k[0])
        print "Plugin RC4 key: " + ''.join('{:02x} '.format(ord(x)) for x in k[1])
        print "Plugin first bytes: " + ''.join('{:02x} '.format(ord(k[2][x])) for x in range(0,8))
        if k[3] == 0:
            plg=pu.reconstruct_pe_header(i)
            plg_name="plugin_"+str(i+1)+".dll"
            with open(plg_name,"wb") as f:
                f.write(plg)
            os.system("upx -d " + plg_name)
        else:
            plg_name="disabled_"+str(i+1)+".plg"
            with open(plg_name,"wb") as f:
                f.write(k[2])
        i+=1  


{% endhighlight %}


<p class="p_title">Conclusion<a name="conclusion"></a></p>



Let's go back to the title of the article and why I believe that this is a direct attack on the business of Ukraine. As I mentioned before, malware starts only on systems where the Ukrainian or Russian keyboard layout is installed. Now let's take a look at the textual header of the plugins.

<pre>
1|:|procmon_rules=tiny.exe|0?81,ifobsclient.exe|0?82,start.corp2.exe|0?83,eximclient.exe|0?84,clibankonlineua.exe|0?85,upp_4.exe|0?86,srclbclient.exe|
0?87,clibankonlineru.exe|0?88,cb193w.exe|0?89,clibank.exe|0?90,pionner.exe|0?91,mtbclient.exe|0?92,mebiusbankxp.exe|0?93,|:||:|
keylog_rules=start.corp2.exe,javaw.exe,jp2launcher.exe,java.exe,node.exe,runner.exe,mtbclient.exe,ifobsclient.exe,bank.exe,cb193w.exe,
clibankonlineen.exe,clibankonlineru.exe,clibankonlineua.exe,eximclient.exe,srclbclient.exe,vegaclient.exe,mebiusbankxp.exe,pionner.exe,pcbank.exe,
qiwicashier.exe,tiny.exe,upp_4.exe,iexplore.exe|:||:|
plugin_size=349428
</pre>


If you look at it carefully, you can see the names of executable files - processes. These files are included in the software packages that Ukrainian banks use in remote service systems! If you list which banks of Ukraine use these systems, then you can see almost all banks in the country will have to list this.


The combination of these two factors gives a confident assumption of an attack on the business of Ukraine, since the systems of remote banking services use small, medium and large businesses in their work.

I also wanted to add that in attacks of this level, the real ip address of the command center is hidden behind a chain of proxy servers to which the loader is trying to connect.

At the time of this writing, the IP addresses of the proxy servers for the command center were
<pre>
nslookup aviatorssm.bit 51.254.25.115
5.23.55.67 - Russia
176.53.161.111 - Russia
89.223.92.75 - Russia
</pre>
These proxies change periodically, but most of them are located in Russia.

This is another indirect factor, the attacks precisely on Ukraine.

p.s. downloaded plugins file you can find on my github page

That's all 


