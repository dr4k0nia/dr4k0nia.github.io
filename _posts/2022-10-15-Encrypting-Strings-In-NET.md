---
layout: post
title:  "Encrypting strings in .NET"
date:   2022-10-15 21:27:24 +0200
categories: dotnet coding
---

Implementing custom string encryption for .NET binaries utilizing an XOR-based cipher and AsmResolver. Encrypting strings is a common practice to slow down static analysis or evade automatic analysis, in this blog post I will explain how I build my own binary-level string obfuscator in C# .NET 6. The full code of the project can be found [here.](https://github.com/dr4k0nia/XorStringsNET)

## Concept and Structure

To begin with, I will explain the concept of my implementation. The following points had to be considered:

- A unique XOR key per string
- Only one universal decryption method
- The decryption method should have as few parameters as possible
- Parameters of the decryption method should be encrypted or encoded

In order to include a unique XOR key per string and reduce the number of parameters needed for the decryption method, some metadata is required. The metadata per string includes the length of the encrypted data and the XOR key to decrypt that data. Using this format all data can be stored in one single data blob. To get a string from the data blob we only need the offset at which the formatted data starts. From that offset, we parse the metadata reading the length first and then the XOR key. 

Additionally to the string data, another XOR key in form of an int is added to the beginning of the data blob. This key serves as the global XOR key used exclusively to decrypt parameters passed to the decryption method.

| Offset | Size | Field  | Description                  |
|--------|------|--------|------------------------------|
| 0      | 4    | Length | Length of the encrypted Data |
| 4      | 4    | Key    | Key to XOR decrypt Data      |
| 8      | n    | Data   | Encrypted Data               |

This table shows how each encrypted string and its metadata are stored in the data blob. First the 8 bytes of metadata then the encrypted string data.

My implementation is split into two projects. First, the runtime, which handles the decryption and stores the encrypted data in the obfuscated binary. The second part is the obfuscator, it injects the runtime into the target binary and handles encrypting the strings as well as rewriting the CIL code to use the string decryption.


## The Runtime

Starting with the runtime, the part responsible for decrypting strings in the obfuscated binary. I will be using an initialized struct for data storage, basically putting raw byte data into a struct. This method is quite appealing for obfuscation since dnSpy and other decompilers by default only show a field and an empty struct with a fixed size but not the raw content. This means locating the encrypted string data is slightly harder in a standard .NET decompiler.

The before-mentioned struct and decryption routine are part of the runtime project which is compiled using netstandard 2.0 to ensure compatibility with .NET Core and Framework at the same time. Since we do not know the contents of the struct before encrypting strings I use an empty placeholder struct which will be patched later by the obfuscator.


Let us take a look at the decryption routine first:

```csharp
public static string Decrypt(int id)
{
    if (id >> 31 != 0) 
        return string.Empty;

    byte* data = (byte*) 0x420;
    
    data += id ^ *(int*)data;
    
    byte[] buffer = new byte[*(int*) data];
    
    fixed (void* ptr = &buffer[0])
    {
        
        cpblk(data + 8, ptr, (ulong) buffer.Length, (ulong) buffer.Length);
    }
    
    int n = buffer.Length - 1;

    for (int i = 0; i < n; i++, n--)
    {
        buffer[i] ^= buffer[n];
        buffer[n] ^= (byte)(buffer[i] ^ *(int*) (data + 4));
        buffer[i] ^= buffer[n];
    }

    if (buffer.Length % 2 != 0)
        buffer[buffer.Length >> 1] ^= (byte)*(int*) (data + 4); // x >> 1 == x / 2
    
    return string.Intern(Encoding.UTF8.GetString(buffer));
}

// Placeholder for cpblk
private static void cpblk(void* destination, void* source, uint bytes)
{
    throw new NotImplementedException();
}
```
<!-- shifting a negative number by 31 will result in -1 every other number will result in 0 -->

At the beginning, it verifies that the provided `id` parameter is a non-negative value. This is done because in the obfuscator empty strings are replaced with calls to the decryption method but instead of a normal value, a negative value is supplied. Empty strings cannot be encrypted with the current logic hence this exception was added.

The variable `data` is assigned a placeholder value, for now. It will later be patched by the obfuscator with the address of the initialized struct.

To find the encrypted string in the data blob the `id` parameter is decrypted using the global XOR key, which is located at the beginning of the data blob. The decrypted result is the offset at which the encrypted string alongside its metadata is located. The offset is then added to `data` the base pointer for the raw data.

Next, a new array is initialized acting as a buffer for the encrypted string data. The size of the buffer is read from `data` by casting it to an int pointer and dereferencing it. Since `data` points to the first value of the string format, which is the length of the encrypted string in bytes. 

Using `cpblk` the encrypted string bytes are copied into `buffer`. The address to copy from is `data` with an offset of 8 added, due to the length and the XOR key stored in front of the string data each taking up 4 bytes. The amount of bytes copied is equal to the length of `buffer`.

The `cpblk`[^1] placeholder method will later be replaced by the obfuscator. It serves as a placeholder for the CIL instruction `cpblk` which has no C# implementation and can therefore only be used by patching or manually constructing CIL code.

After copying the encrypted bytes to `buffer` they have to be decrypted. Using a loop with 2 indexing variables `i`, which starts at index 0, and `n`, which starts at the last element of `buffer`. While `i` increases with each iteration `n` decreases with each iteration. Using the [XOR swap algorithm](https://en.wikipedia.org/wiki/XOR_swap_algorithm) on the elements at index `i` and `n` in the loop we reverse the order of bytes in `buffer`. 

At the same time, the swapped byte is decrypted using another XOR with the unique string key which is read by casting `data` with an added offset of 4 to an int pointer and dereferencing it. Since the loop does not account for the "middle" byte of odd element count arrays, a check was added to decrypt said byte. First using remainder to check if the element count of `buffer` is odd if that is the case get the byte at the index, length of `buffer` right shifted by 1 (equivalent to diving by 2). Then XOR decrypt the byte at said index with the unique string key just like in the loop.

Finally, use `Encoding.UTF8.GetString` to convert the decrypted `buffer` into a UTF8 formatted string. With `string.Intern` to take advantage of the .NET runtimes string caching capabilities.

[^1]: [MS Documentation for cpblk](https://docs.microsoft.com/en-us/dotnet/api/system.reflection.emit.opcodes.cpblk)


## The Obfuscator

We will use two classes first the StringEncryption class, which is the main part of the obfuscator responsible for parsing the .NET target binary using AsmResolver. The second class we will use is the EncryptionService class which handles encrypting the strings and stores the encrypted data until it is injected into the target binary.

In the StringEncryption class, we start by injecting the runtime. Using AsmResolvers `MemberCloner` to clone the decryption method from our runtime DLL into the target binary. We resolve the injected decryption method, and the placeholder for `cpblk` and store the resolved methods for later use.

After we injected the runtime, we go through all types that have any methods. Next, we iterate over all methods, skipping methods that don't have a `CilMethodBody`. Now we can iterate over the CIL instructions and filter out only `Ldstr` instructions. Once we find a `Ldstr` instructions we will need the EncryptionService class. It handles the encryption of strings and stores all encrypted Data. It has three properties:

| Property | Description |
|--------|------|
| `Index` | Encrypted version of the current offset in the encrypted data blob |
| `Length` | The total length of the encrypted data in bytes.|
| `Data` | The encrypted data as a byte array.|

If the operand of the `Ldstr` instruction is an empty string, we do not encrypt it but instead patch the instruction with an `Ldc.I4` that has the negated value of `Index` as operand. We negate the value since the runtime identifies empty strings by negative values and handles them in the special way discussed in the first part. After we patched the `Ldstr` instruction we insert a `call` instruction with the injected decryption method as its operand.

After processing all methods we need to do some patches in the injected runtime. First, we need to set up the placeholder struct with the correct attribute values. The struct needs a `ClassLayout` with packing size 1 and the length of the encrypted data as its size.

We also need to create a new field which will be an initialized version of our struct. By adding a `DataSegment` in its `FieldRva`, we can use the field to store any raw data we want, in this case, our encrypted string data.

The last part is patching the placeholder values in the decryption method. For that, we will resolve the `Ldc.I4` instruction that has `0x420` as its operand and patch it with a `Ldsflda` instruction that has our field as its operand. `Ldsflda` will push the address of the field on the stack. Since the field holds our data the pushed address will point to the base of our encrypted data blob.

Additionally, we also need to patch the placeholder for `cpblk` for that we simply resolve the call instruction which has the placeholder method as its operand and replace it with a `cpblk` instruction. We can then remove the placeholder method since it is no longer required.

Once we have replaced all placeholders and removed the unused method, we can write the modified target binary to disk. You now have a binary with fully encrypted strings.
