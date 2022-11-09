---
layout: post
title:  "Writing a simple Unpacker"
date:   2020-10-31 16:46:24 +0200
categories: dotnet reverse-engineering
---

Unpacking simple protections of common confuserex mods and other open source obfuscators. This write up was made for beginners, so if you are an experienced reverse engineer its probably not for you. Basic knowledge of C# and CIL is assumed. Keep in mind that the concepts and code shown are my approach, it can be done in different ways for example using emulation.


### Contents:
1. Getting started
2. Deconstructing protections
3. Credits

## 1. Getting started
<p>
I got the idea of writing a custom unpacker to solve mutations/protections that could not be solved by de4dot after coming across more & more ConfuserEx modifications using "custom" protections that could not be unpacked by de4dot, an example would be using sizeof() for integer mutations. Those are quickly removed but doing it manually is quite time wasting. So I decided to write a tool for it.
</p>
<p>
I chose AsmResolver as an assembly editing library. I started out by taking a look at the protections that I wanted to fix. To remove a protection we will first need to understand how the protection works. In my case the source code of most of the protections themselves was available in quite a few public ConfuserEx forks. But even if the source is not available we can determine how a protection works by decompiling a sample.
</p>


## 2.0 Deconstructing: Sizeof Mutations

A very common example are `sizeof()` mutations found in numerous public ConfuserEx forks. The most basic version looks somewhat like this:

Lets say our original code looks like this: 
```csharp
int a = 256
```

Now we run it through an obfuscator using `sizeof()` mutations, the result could look like this:

```csharp
int a = 260 - sizeof(int);
```

The simple variable has been converted into an expression, `sizeof(int)` will return a value of 4 [(sizeof msdn)](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/operators/sizeof). So its basically just `int a = 260 - 4`.
`<br>`While de4dot will simplify `int a = 260 - 4` to `int a = 256` it will not simplify the expression containing `sizeof(int)` so to fix this we will need to get rid of the sizeof.

To understand how we can remove the sizeof from our expression we will first need to take a look at the CIL Code of our expression.

```
ldc.i4 260
sizeof System.Integer
sub
```

- `ldc.i4` OpCode with the operand value of 260 initializes an integer with said value.
- `sizeof` OpCode with the operand System.Integer represents `sizeof(int)` which will result in a integer value of 4.
- `sub` OpCode stands for subract (-).

<br>
To get rid of the sizeof we will resolve its resulting integer value and replace the sizeof OpCode with an integer *(ldc.i4 OpCode)*. I will explain the concept below:

1. Get all Types and their methods
2. Foreach method that has a CILBody check if the instructions contain sizeof OpCode(s)
3. For every found sizeof OpCode call `GetImpliedMemoryLayout(is32Bit true/false)`¹ *(feature of AsmResolver)* If you dont use AsmResolver you can run a dynamic method that calls `sizeof(T)`. T being the the operand type of the sizeof OpCode².
4. Replace the sizeof OpCode with an ldc.i4 OpCode and set its operand to the value thats returned by GetImpliedMemoryLayout.
5. Call OptimizeMacros() to optimize CIL like `ldc.i4 1` to `ldc.i4.1`

My full code can be found [here](https://github.com/dr4k0nia/Unscrambler/blob/master/Unscrambler/Features/MethodFeatures/SizeOfReplace.cs)

_<font size=2> 1. This assumes that you have before determined if the code is 32bit or not. If the code is 32bit call the method with the parameter true else use false.</font>_
<br>
_<font size=2> 2. This requires reflection while AsmResolvers method is completely static. </font>_

## 2.1 Deconstructing: Locals to Fields

Another example found in numerous forks of ConfuserEx is the locals to fields protection it basically does what the name says it converts locals to field. Since de4dot will not simplify expressions that include field values we want to restore the fields back to locals.

The examples I have found during my research mostly work somewhat like this:

- OpCodes like stloc, ldloc and ldloca are replaced with their field equivalents stsfld, ldsfld, ldsflda
- The replacement fields are created in the global type¹, `<Module>` by default. These fields will have the attributes: public and static.
- (Optional) Sometimes one field is used to replace multiple locals of the same type, for example all locals of the type int are replaced with the same field.

_<font size=2> 1. The fields could also be created in any other public type, but all forks I looked at used the global type. </font>_

Lets say the original code looks like this

```csharp
string text = SomeMethodThatReturnsAString();
if (text.Length > 0)
{
    Console.WriteLine(text);
}
```

After running it through an obfuscator using locals 2 fields we will receive something like this. Instead of to a local the string returned by `SomeMethodThatReturnsAString()` is now assigned to a field thats intialized in the global type.

```csharp
<Module>.Field0 = SomeMethodThatReturnsAString();
if (<Module>.Field0.Length > 0)
{
    Console.WriteLine(<Module>.Field0);
}
```

Looking at the IL of the above shown code shows how minor these changes actually are. First we will look at the CIL Code of our original code. *(code is simplified)*

```
call string C::SomeMethodThatReturnsAString()
stloc.0
ldloc.0 
callvirt instance string [mscorlib]System.String::get_Length()
ldc.i4.0
...
ldloc.0
call void [System.Console]System.Console::WriteLine(string)
...
```

If we compare this to the obfuscated CIL Code it looks very similar. The OpCodes that set and load our locals value have been replaced with their field equivalents.

```
call string C::SomeMethodThatReturnsAString()
stsfld string <Module>::Field0
ldsfld string <Module>::Field0
callvirt instance int32 [System.Private.CoreLib]System.String::get_Length()
ldc.i4.0
...
ldsfld string <Module>::Field0
call void [System.Console]System.Console::WriteLine(string)
...
```

So to convert the fields back to locals we will do the following:

1. Search for fields that match the criteria (!private and static, has no default value, only used in one method) in the global type
2. Check all method bodies for OpCodes were the operandtype is InlineField and the operand is a FieldDefinition
3. Check if the matched FieldDefinition is one of the fields that we gathered from the global type:
   - if true: Add new local with the same type as the fields type, change all calls to the matched field with the newly created local. Store the replaced field and new local in a dictionary. Check if there is already a local for the matched field. If there is already an entry for the field use the entry from the dictionary.
   - if false: skip
4. (Optional) Call OptimizeMacros()
5. (Optional) Remove all fields that were replaced. In my case the ones from the before used dictionary.

My full code can be found [here](https://github.com/dr4k0nia/Unscrambler/blob/master/Unscrambler/Features/LocalsToFieldRemover.cs)

## 2.2 Deconstructing: Math Mutations

Another protection that can be seen quite often in modified ConfuserEx versions, or standalone obfuscators. Are math mutations, using System.Math methods like `Floor()` and `Ceiling()` to generate expressions or replace simple integers.

We will start with the original code again:

```csharp
int a = 256;
```

Now the obfuscated one. As you can see its quite hard to guess the original number of our integer now.

```csharp
int a = (int)Math.Floor(102402.0) - 102146;
```

What the obfuscator has done is create an expression that will result in our original integer. I will not go in to the details of how that is achieved as it is not that important for unpacking this protection. Lets look at the CIL Code of the obfuscated snippet.

```
ldc.r8 102402
call float64 [System.Private.CoreLib]System.Math::Floor(float64)
conv.i4
ldc.i4 102146
sub
```

- `ldc.r8` OpCode represents the parameter supplied to `Math.Floor()` its operand is the value
- `call` OpCode will call `Math.Floor()` with the above supplied value
- `conv.i4` OpCode casts the result of `Math.Floor()` to integer. Which is required since the second value of the expression is an integer (ldc.i4)
- `ldc.i4` OpCode pushes an integer with the value of its operand onto the stack
- `sub` OpCode stands for subtract (-)

In order to make this fixable by de4dot we will need to get rid of the `Math.Floor()` so what we will do to archieve this is the following:

1. Check method bodies for instructions which operand is a MemberRef with the DeclaringTypes FullName equal to System.Math
2. Use Reflection to resolve the method using the resolved MemberRefs MetadataToken (make sure to resolve it from the original System.Math class)¹
3. Check the methods parameter count
4. Get the parameters required from the instructions operands, and Nop the instructions. Implement a check that only includes constant types if the obtained params are not a constant type continue (skip further processing)
5. Invoke the method with the paramters obtained before
6. Replace the call instruction with the OpCode related to the return type of our math function in this case ldc.r8 and set its operand to the result returned by the invoked method

_<font size=2>1. This will fail if the target app uses a different framework, to do it properly we would have to resolve the target framework and use its math class. Fix will be added later</font>_

My full code can be found [here](https://github.com/dr4k0nia/Unscrambler/blob/master/Unscrambler/Features/MethodFeatures/MathReplace.cs)

## 2.3 Deconstructing: Calls to Calli

Calls to Calli can be found in most ConfuserEx forks however the implementation thats commonly used is not very effective.

For this example we will skip looking at the C# Code and checkout the CIL Code instead. Lets start with the original code

```
call void [System.Windows.Forms]System.Windows.Froms.Application::EnableVisualStyles()
```

If we look at the CIL Code produced by the calls to calli protection, we can see that the ldftn OpCodes operand is the same as the call OpCodes operand in the unobfuscated code, with a little thinking it is pretty obvious how simple the fix will be.

```
ldftn void [System.Windows.Forms]System.Windows.Froms.Application::EnableVisualStyles()
calli void()
```

To get rid of the calli protection we will do the following:

1. Search method bodies for calli OpCodes that are lead by ldftn OpCodes
2. Remove the calli OpCode and Change the ldftn OpCode to call

My full code can be found [here](https://github.com/dr4k0nia/Unscrambler/blob/master/Unscrambler/Features/MethodFeatures/CalliReplace.cs)

## 3. Credits

- [AnonymooseRE](https://github.com/anonymoosere) For helping out with Unscrambler and answering a lot of my questions
- [Washi](https://github.com/Washi1337/AsmResolver) For AsmResolver and answering my questions
