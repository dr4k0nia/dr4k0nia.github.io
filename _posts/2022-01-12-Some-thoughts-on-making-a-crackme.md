---
layout: post
title:  "Some thoughts on making a crackme"
date:   2022-01-26 00:13:24 +0200
categories: dotnet reverse-engineering
---

In the last few weeks, I've been taking a closer look at crackmes, especially beginner focused ones. And noticed a few things that I think many new developers get wrong. Therefore this is a little bit of personal advice for beginner crackme challenges. I will only focus on C# code in this write up however some of the ideas apply to other languages as well.

## What is a crackme?

A crackme is usually a reverse engineering challenge that implements some kind of vulnerable key/password verification system. The task for the user is to circumvent or reverse engineer the system to either login successfully or access a hidden flag. There are different formats of these challenges out there but I will mainly focus on the before mentioned formats.

## Do not rely on clear text key comparisons

A lot of people use very simple checks like a clear text string comparison with a hardcoded key. Instead of a more sophisticated check, they then rely on heavy obfuscation. The issue with that is, the check itself is still just a clear text comparison. This means no matter how heavily obfuscated the code is, the actual key will be in memory when it gets compared to the user input. Which makes solving them quite trivial. I will be focussing on challenges that use the string equality comparer to check user input against a hardcoded password usually stored in encrypted form.

<br>

**Using a debugger**

A very simple way to defeat a challenge that relies on a simple string comparison is using a debugger like dnSpy. In many languages, string comparisons are implemented using a function or a method, and .NET is no exception. Therefore, you can place a breakpoint on the method responsible for string comparisons. When the method gets called during the key verification all you need to do is wait for your breakpoint to hit and read the used parameters in the locals window. In my example, I placed a breakpoint on the `==` operator in mscorlib `System.String` which is used in most crackmes that implement the previously described process. If you want to catch all string equality comparisons I would recommend placing the breakpoint on `string.Equals` instead.

![Breakpoint on string equality comparer](/images/stringequals_breakpoint.png)

Now some challenges use anti debugging code to prevent dynamic analysis like this. Luckily for us dnSpy already can circumvent basic debugger detection. For example, it prevents detection via the `System.Diagnostics.Debugger` class, `kernel32!IsDebuggerPresent` and `kernel32!CheckRemoteDebuggerPresent`. There are also other ways to detect debuggers, one very commonly used technique is calling `ntdll!NtQueryInformationProcess` to check the `ProcessDebugPort` which will be non-zero when the process is run under a debugger[^1]. However, quite a lot of people seem to fail at the implementation level. In many cases, I encountered anti debugging code that only runs once in the module constructor which makes it really ineffective since we just need to wait for the debug detection to run at the beginning, after that we can attach our debugger without any issue.

[^1]: [Microsoft NtQueryInformationProcess Documentation](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess)

<br>

**Method Hooking**

Say we encounter an app that has properly implemented anti debugging and patching would be inconvenient due to anti-tamper measures. It can therefore be difficult to rely on a debugger alone. Instead of a debugging, we can also hook the string equality comparer and intercept the parameters. To prove how easy this is I wrote a tool that should work on most challenges that rely on string equality comparisons. You can view the full source code [here](https://github.com/dr4k0nia/NoChallenge).

The tool works by loading the crackme executable using Reflection. Once we loaded the executable, we can place our hook on `string.Equals` and invoke the entry-point of the executable. Since the Reflection loading part is quite boring I will not go into much detail and focus only on the hooking part.

I am using the Harmony library for hooking. So to get started we initialize a new Harmony instance which will allow us to perform hooks and patches on our current AppDomain. We will use the Harmony instance to apply a patch to the `string.Equals` method, specifically a prefix hook. Prefix hooks are executed before the hooked method is executed, which allows us to intercept and modify the parameters.
By calling `Patch` from our Harmony instance we install the hook. All following calls to `string.Equals` will now be processed by our callback before the actual method is called.
Lets take a look at the callback code.

```csharp
private const char Key = '§';

[HarmonyPatch(typeof(string), nameof(string.Equals))] 
public static bool Prefix(string a, string b)
{
  // Skip invalid input
  if (a is null || b is null)
    return true;

  // Skip empty strings
  if (a.Length == 0 || b.Length == 0)
    return true;

  // Skip if none of the inputs starts with §
  if (a[0] != Key && b[0] != Key)
    return true;

  // Take the value that does not start with Key
  string solution = a[0] == Key ? b : a;

  Console.BackgroundColor = ConsoleColor.Green;
  Console.ForegroundColor = ConsoleColor.White;

  // Print out solution and write it to file
  Console.WriteLine("Solution: {0}", solution);
  File.WriteAllText("solution.txt", solution);

  return true;
}
```

The method has a `HarmonyPatch` attribute which is required by Harmony to specify that a method can be used as a patch. The callback accepts two strings just as the original method. We will need to do a null check first since the supplied parameters can be null. If the null check hits or the one of strings is empty we return true. If we return true in a Harmony prefix hook it will skip the rest of the callback code and invoke the original method instead[^2]. The last check is to make sure we only print out the intercepted parameters when our specified char `'§'` was supplied as input. This means that you have to enter `§` in the crackme when using the tool. I choose the `§` character since it is a rather uncommon character so we can be pretty certain that if a string starts with that char it is our input. Our input will be compared to the actual password which is why the string that does not start with `§` should be the solution. Once we found our potential solution we print it in the console and also write it to disk.

[^2]: [Harmony Prefix Patching](https://harmony.pardeike.net/articles/patching-prefix.html)

<br>

**Deobfuscation**

Another technique to defeat a clear text key comparison is plain old deobfuscation. Since the key is present in the binary one way or another we can just try to find the method responsible for decrypting or constructing the string and get its result so we can read the actual string directly in the decompilation. Luckily for us, there is a great tool called de4dot. We can leverage de4dot's emulator and clever Reflection usage to decrypt strings. We just need to provide de4dot with the information on what the decryption methods are so it knows what to emulate and invoke. To get that information we will need to do some manual analysis first. To make de4dot decrypt the strings we want, we need to supply it with the metadata tokens of the decryption methods. We can find these tokens using dnSpy.

![dnSpy Token](/images/decryption_token.png)

After obtaining the token we can use de4dot's command-line arguments to make it decrypt all occasions of the decryption method we found. See the example below:

```
de4dot <path to crackme executable> --strtyp delegate --strtok 0x06000004
```

If there are multiple decryption methods you can simply append `--strtok 0x06000000` to the arguments for each decryptor token. Since writing out command-line arguments every time can be a bit annoying I made a little GUI app that will construct the arguments and run de4dot for us. Usage should be self-explanatory, drag & drop the executable you want to process. Select a decryption mode: delegate or emulation. Enter the decrypter tokens. And press the "Deobfuscate" button to make de4dot do its work. The tool can be found [here](https://github.com/dr4k0nia/de4dot_gui).

<br>

## Writing a simple crackme that does not rely on clear text comparisons

What can we do instead of just comparing the user input to our password/key? My suggestion is to encrypt the user input using a deliberately vulnerable cipher, and compare it to the actual key that is stored in an encrypted form. This way we do not expose the clear text key as it is only compared in encrypted form, this means it cannot simply be obtained by placing a breakpoint on or hooking the string equality comparer. The key can be decrypted, however the actual decryption method is not present in the application. Which means a reverse-engineer would have to reconstruct the decryption routine based on the encryption routine. Keep in mind that the cipher used for encryption has to be vulnerable so it can be reversed, or brute-forced if that's the objective you're after.

I will be implementing my example as a console application. The code is written in .NET 6 using the new template.

```csharp
Console.WriteLine("Enter the correct password:");
string? solution = null;
while (solution == null)
{
    string? input = Console.ReadLine();
    solution = Verify(input);
}

Console.WriteLine($"The password is: {solution} Good job :)");
```

I am not a fan of crackmes that just kill the process or break if you enter an incorrect password. Therefore I implemented a while loop to run as long as no correct key was entered instead. I use a nullable string variable as the loop condition, in the `Verify` method I only give out a non-null value when the password is correct. This is only the main method the actual interesting part is the verification method so let's take a look at that next.


```csharp
static string? Verify(string? input)
{
    // Skip any checks if the input is invalid
    if (input == null)
        return null;

    // This is our key in encrypted form
    char[] secret =
    {
        'ä', 'ù', 'å', 'è', 'î', 'æ', 'î', 'Õ', 'Ý', 'è', 'þ', 'Ñ', 'ì', 'ø', 'â', 'ù', 'Ì', 'ù', 'Ö', 'É', 'æ', 'Ç',
        '×', 'Û', 'Þ', 'ā',
    };

    // hint that the password is the same length as secret
    if (input.Length != secret.Length)
        return null;

    // Buffer that will hold the encrypted form of input
    char[] buffer = new char[input.Length];

    // Encrypt the user input
    for (int i = 0; i < input.Length; i++)
    {
        char c = input[i];
        c += (char) 0xEA;
        c ^= (char) 0x7E;
        c -= (char) (0x5B + i);
        buffer[i] = c;
    }

    int sum = 0;
    // Compare the encrypted user input to secret
    for (int i = 0; i < buffer.Length; i++)
    {
        sum |= buffer[i] ^ secret[i];
    }

    if (sum == 0)
        return input;

    // Return null if input does not match secret
    return null;
}
```

We start with some basic checks that will abort the actual check if the key is null or not the correct length. The length check is already a hint to the reverser that the input needs to be the same length as `secret`. After these basic checks, we do some simple encryption using `input`. We iterate over each character of `input` performing some calculations then writing the result to `buffer`. 
<br>
We compare the encrypted result that is stored in `buffer` with `secret`, which is our password encrypted by the same cipher. We do that by defining the integer variable `sum` which is zero. We do a loop and XOR each char of `buffer` with the char at the same index in `secret`, since a number xored with itself is always zero the result will be zero if the characters match. We take the result to perform a logical OR operation with `sum`, which will change the value of `sum` should the result be non-zero. 
<br>
If `buffer` equals `secret` the value of `sum` stays zero and we return the value of `input` which will end the while loop seen in the main function and output the solution. If they do not match we simply return null and the while loop continues.

Now how would you reverse engineer this if the password is encrypted?
Lets think of the logic in `Verify` again:

> Get Input &rarr; Encrypt Input &rarr; Compare encrypted version of input with secret &rarr; Return result

Looking at this we know that `secret` has to be encrypted in the same way as `buffer` which means we know how the encryption works. But how do we use this knowledge? Let's take a closer look at the encryption it uses addition, subtraction, and XOR. All of these operations are reversible which means we can calculate the original password by reversing the operations performed for encryption. So first we will need to reverse the order of the operations meaning first the subtraction then the XOR and finally, the addition since we are doing the process backwards. We also need to convert addition and subtraction to their counterparts, meaning we need to add `0x5B + i` and subtract `0xEA` to get the original value. The XOR algorithm works for encryption and decryption so we do not need to change it.

What would the code to decrypt `secret` look like? Well, this I leave as an exercise to the reader :) The full code of the crackme example can be found [on my gist](https://gist.github.com/dr4k0nia/e595ef2b63c417610879f61a78a2ab81). If you have any questions or want to show me your solution you can reach me on discord: drakonia#1110

This example is of course really basic and not secure. But it is only meant to give you an idea of how to write a crackme that does not use clear text comparisons. You can easily improve this by increasing the complexity of the cipher or making the key verification happen in multiple steps etc. You are free to do whatever you want! But if you use a format like this keep in mind that the cipher has to be reversible somehow. A great way to test if your challenge is solvable is by trying to solve it yourself.

I hope you could gather some ideas for your next crackme or maybe even your first crackme.

<hr>