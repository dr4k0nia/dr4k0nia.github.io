---
layout: post
title:  "Unpacking OriginLogger Builder"
date:   2022-09-20 16:46:24 +0200
categories: dotnet reverse-engineering
---

# Unpacking OriginLogger Builder

OriginLogger is a keylogger that shares a lot of similarities with the well-known Agent Tesla malware. Today I will take a look at their builder and unpack it. A little spoiler the sample used in this post was protected with a trial version of the commercial obfuscator Eazfuscator.NET which stops the binary from running due to the expired trial version...

You can find the sample on [malshare](https://malshare.com/sample.php?action=detail&hash=595a7ea981a3948c4f387a5a6af54a70a41dd604685c72cbd2a55880c2b702ed)


# Initial Analysis

Opening the sample in dnSpy will show a lot of errors in the decompilation. Looking at the IL will reveal some invalid code. This is an indicator of method body encryption. Looking at the module constructor verifies that assumption. The first method called by the constructor at token `0x06000006` is responsible for decrypting the method bodies.

![constructor](/images/origin_decrypt.png)

Looking at the method we can quickly deduce what it is approximately doing. It starts with obtaining the `HINSTANCE` of the current module. Which is a pointer to the base of the currently loaded module aka the PE header base. To that pointer, it adds `0x3C` which points to `e_lfanew` a field in the PE header which holds the file address of the new executable header. The value of `e_lfanew` is added to the base pointer and then used to read another value by adding offset `0x06` which points to `NumberOfSections`. The number of sections is stored in a local for later use. Next, it reads from offset `0x14` which points to `SizeOfOptionalHeader` this is important since the size of this part of the PE header varies depending on bitness. Using the size and offset `0x18` which points to the beginning of the section table. From there the code loops through the section table entries to find its custom PE section in which the encrypted method bodies are stored. It will then decrypt the method bodies. (I shortened this explanation due to time constraints)

## Dumping

To get the unencrypted method bodies, I will debug and dump the file. Start by placing a breakpoint on the second call in the global module constructor. We can safely ignore the anti-debug code in the method decryption routine since dnSpy by default hooks `CheckRemoteDebuggerPresent` and `IsDebuggerPresent` to avoid detection.

![breakpoint](/images/origin_constructor.png)

Once the breakpoint hits open the Modules tab and right-click the main module. Save it to disk.

![dumping](/images/origin_dump.png)

Now open the saved module and patch both calls in the global module constructor with a NOP instruction, since we don't need to decrypt methods anymore and the second call is runtime anti dump which we also don't need. Save the changes.

## Deobfuscating

Next, we will use [de4dot](https://github.com/de4dot/de4dot) to get rid of the Unicode names. Simply drag & drop the dumped and patched binary into de4dot and let it do its work. After de4dot has finished we are left with the string encryption for that we will use a tool called [eazfix](https://github.com/HoLLy-HaCKeR/EazFixer) make sure to use the `--keep-types` argument. Eazfix will decrypt the strings for us, if you're curious how it works it uses Harmony to patch the stackframe calls used by Eazfuscators string encryption. After patching the stackframe method to always return the string decryption method it can simply invoke the string decryption routine for each string and patch the call with the resulting string.

As soon as eazfixer is done you have a fully unpacked Origin Loader sample ;)
