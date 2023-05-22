---
layout: post
title: NixImports a .NET loader using HInvoke
date: 2023-05-22 15:27:24 +0200
categories: dotnet malware redteam
---

A while ago, I released [HInvoke](https://dr4k0nia.github.io/posts/HInvoke-and-avoiding-PInvoke/), a project showcasing API hashing for managed functions. The initial release was rather basic and lacked desirable features like support for non-static methods. NixImports is an example showing the use of the new HInvoke. The update includes support for non-static methods as well as support for nonunique method names. In this blog post, I will describe the improvements and showcase the use of HInvoke in a simple .NET loader.

## The Concept 

NixImports aims to build a loader with little to no direct function calls and reduce referenced methods to a minimum. Importing a function in .NET adds some metadata, for example, the namespace and name of the referenced method. This metadata gives away potential capabilities of our binary and can be used for detection, see for example, GDATA's [TypeRefHash](https://www.gdatasoftware.com/blog/2020/06/36164-introducing-the-typerefhash-trh). To avoid this kind of metadata as much as possible, NixImports uses my managed API hashing implementation HInvoke. HInvoke does not require the method we want to invoke to be referenced in the assembly; instead, it will dynamically resolve the method or property on runtime, using only two hash values to identify the target method.

### HInvoke

As mentioned above HInvoke requires two hash values. The first hash identifies the `FullName` of the type containing our targetted member. The second hash identifies the method or property we want to access. To resolve the desired type and member, HInvoke iterates through all types of `mscorlib` and generates a hash for each type name; once a matching hash is found, it will iterate through all methods or properties of that type and hash their name or in case of methods `ToString` value. If the hash matches the supplied second hash, we return the property value or invoke the method and return its result. HInvoke also accepts arguments for the to-be-called method and an instance object for methods and properties. Using the instance object, HInvoke can invoke non-static methods or get properties of instantiated types. To minimize overhead, I added a cache that holds previously resolved member info to avoid expensive re-parsing of `mscorlib`.

### Storing Payload Data

Besides hiding imports, I wanted to have fun hiding the payload data. We take the payload data and split it into smaller chunks. Next, we Base64 encode the chunks as strings. The encoded strings are then encrypted with a simple ROT cipher and used as names for newly injected methods. The injected methods contain some placeholder code but serve no purpose except storing payload data in their name. During runtime, we ensure the correct order of methods and decrypt the names before converting them back to bytes through Base64 decoding. To make sure we parse the methods in the correct order, I use AsmResolvers `TokenAllocator`, which allows us to pre-assign tokens to injected methods. After adding the payload data, I patch the loader stub replacing placeholder values with the pre-assigned tokens.


## The Runtime

Now let us look at the most exciting part of NixImports, the actual loader code. The loader utilizes HInvoke to conceal its function calls and deliberately avoids using traditional functions that analysis tools and EDR software may detect. Wherever possible, NixImports uses the underlying internal functions instead of the public functions. For example, it uses `RuntimeAssembly.nLoadImage` instead of `Assembly.Load`. If you take a look at `Assembly.Load` in a decompiler you will see that it performs some sanity checks before calling `RuntimeAssembly.nLoadImage`. We skip the sanity checks and call the internal function directly. 

Let us take a look at the code responsible for parsing the Base64 encoded method names.
```csharp
byte[] payload = new byte[0x1337];  
int offset = 0;  
for (int i = 0x1338; i < 0x1339; i++)  
{  
    MethodBase baseMethod = InvokeMethod<MethodBase>(1274687369, 1074927592, new object?[] { i }, module); 
    string name = GetPropValue<string>(4243846143, 1642051212, baseMethod); 
    fixed (char* ptr = name)  
    {        
	    int length = GetPropValue<int>(1845477325, 4202415711, name);
        for (int j = 0; j < length; j++)  
        {            
	        ptr[j] -= (char)(_methodCache.Keys.ToArray()[0] % 100 - 30);  
        }  
        byte[] data = base64FromCharPtr(ptr, length);  
        InvokeMethod<short>(2132718223, 4285503295, new object?[] { payload, offset }, data);
        offset += data.Length;  
    }
}
```
*Note that `0x133X` values are temporary placeholders and will be replaced after injection. The `base64FromCharPtr` delegate is dynamically initialized and resolved via HInvoke.*

All notable calls have been replaced with a call to the HInvoke handler, leaving only the return type as an obvious indicator of its purpose. It's important to note that the return type cannot be relied upon because we can select any type we want as the generic parameter if the method does not have a return value. Before writing the final image to disk, the packer will also rename all members in the runtime to random Unicode strings, further obscuring the code.

As described above, this code loops through all methods that contain payload data. It uses `MetadataToken` values to resolve the methods using Reflection. The first handler resolves the method the second handler retrieves its name. Then we get a pointer to the string and decrypt it char by char using a slightly obscured subtraction of `65`, the numeric value of the uppercase A in the ASCII encoding. After decrypting the string, we use the dynamically resolved delegate `base64FromCharPtr` to convert the Base64 string back to bytes. The resulting byte array is then copied into the large array initialized at the top, which will later contain the entire payload image.

```csharp
var assembly =  
    InvokeMethod<Assembly>(3909091325, 1082111880, info); //System.Reflection.RuntimeAssembly.nLoadImage  
  
var entryPoint =  
    GetPropValue<MethodInfo>(4078926558, 3155696631, assembly); // System.Reflection.Runtime.EntryPoint  
  
object[] parameters =  
    new object[InvokeMethod<ParameterInfo[]>(1891508174, 4164820959, null, entryPoint).Length];  
if (parameters.Length != 0)  
    parameters[0] = args;  
InvokeMethod<object>(1891508174, 4026509245, new object?[] { null, parameters },  
    entryPoint); // System.Reflection.MethodBase.Invoke(object, object[])
```

After the image has been reconstructed, it is loaded into our `AppDomain` using `nLoadImage`. Next, the entry point is resolved and called, passing any command line arguments supplied to the loader stub to the payload. Support for dynamic libraries is not implemented since they do not have an `EntryPoint` property. Pull requests are always appreciated if you would like to add support for dynamic libraries.

## The Analysts Perspective

Now let us take a look at a packed image produced by NixImports in dnSpy. Apart from reducing import references HInvoke also does a great job as an obfuscator. As we can see most of the code is made up of calls to HInvoke handlers. We can see some return types of the handler methods but no direct references to any functions. The renaming obfuscation applied makes the code even less readable.

![](/images/niximports/nix_loader_dnSpy.png)

Most analyst's first thought would likely be to run the binary through de4dot. However, de4dot would destroy the loader by renaming the methods containing the encoded payload bytes, a nice side effect increasing the difficulty of pure static analysis.

![](/images/niximports/nix_references.png)

By checking the Type References in dnSpy, we can evaluate the imported types and their members. This info can give some valuable insights into the capabilities of a program. Using HInvoke, we should not find any references to the methods and properties we accessed through its handlers. Let us check:

-  `Assembly` is imported but only references `GetTypes`, with no references to dynamic assembly loading.
- The assembly contains no references to `Convert` which contains Base64 encoding-related methods

Success! The loader's assembly is missing typical indicators that one would expect to be present in a loader. In case you want to use it or experiment with it yourself, checkout the [GitHub repository](https://github.com/dr4k0nia/NixImports)

## Tips for Defenders

After discussing how NixImports operates, let's now examine potential detection methods. The current implementation has a few flaws, that allow for static detection. A few indicators that come to mind when I thought about possible detection are:

- Hardcoded hash values used within the code
- The hashing algorithm itself
- Hardcoded encryption: We can search for known text values, since we know what they will be in their encrypted form.

Based on these indicators, I created a simple Yara rule. The rule consists of two patterns. The first one represents the encoded MZ header of the payload . The second pattern covers the initialization of the delegate for `Base64FromCharPtr`, which happens right at the beginning of the loader code. The `$a` strings represent imports required by HInvoke.

```text
rule MAL_Msil_Net_NixImports_Loader {
   meta:
      description = "Detects NixImports .NET loader"
      author = "dr4k0nia"
      date = "2023-05-21"
      reference = "https://github.com/dr4k0nia/NixImports"
   strings:
      $op_pe = {C2 95 C2 97 C2 B2 C2 92 C2 82 C2 82 C2 8E C2 82 C2 82 C2 82 C2 82 C2 86 C2 82} // PE magic
      $op_delegate = {20 F0 C7 FF 80 20 83 BF 7F 1F 14 14} // delegate initialization arguments

      // Imports that will be present due to HInvoke
      $a1 = "GetRuntimeProperties" ascii fullword
      $a2 = "GetTypes" ascii fullword
      $a3 = "GetRuntimeMethods" ascii fullword
      $a4 = "netstandard" ascii fullword
   condition:
      uint16(0) == 0x5a4d
      and filesize < 3MB
      and all of ($a*)
      and 2 of ($op*)
}
```
