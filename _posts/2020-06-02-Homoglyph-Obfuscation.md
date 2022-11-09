---
layout: post
title:  "Homoglyph Obfuscation"
date:   2020-06-02 16:46:24 +0200
categories: dotnet coding
---

A while ago I watched a very interesting DEF CON talk called "Repsych: Psychological Warfare in Reverse Engineering" by Chris Domas. In his talk Chris talked about how one could fool and or annoy reverse engineers with some little tricks. This got me thinking what can I do in .net to annoy and or fool reverse engineers. After reading about homoglyphs I had a fun little idea.

## What are homoglyphs?
Homoglyphs are characters that look similar or equal to the default alphabetical characters, however they are actually from different alphabets. For our obfuscation concept, we will abuse the fact that that these characters look almost exactly like normal letters.

## How can we use homoglyphs?
So since the homoglyph characters look just like latin characters, we can use them to have to identical looking names that are actually different. For example we could replace the character M in the name ```<Module>``` with an M from a different alphabet.

**Example:**
```
//normal latin characters
<Module> => <Module>         

//replaced character M 
<Мodule> => xn--<odule>-tig
```
You can check if a word contains a homoglyph character using [Punnycoder](https://www.punycoder.com/)

![example in dnSpy](https://i.imgur.com/OvyKYjx.png)

This is the example from above with a few variations of homoglyphs, as you cann see all of the names look exactly the same in dnSpy. But only the first ```<Module>``` is the real global type. An experienced reverse engineer will probably know that the first one always is the real one. However its still a funny little annoyance :) If you want to, you can do this to any name, for example ```Main()```. Keep in mind this is rather a little annoyance than an actual protection.

## How to do it yourself
1. **Getting Homoglyphs:**
Finding the homoglyph characters yourself is annoying and takes time...
Thankfully irongeek made a perfectly working "Homoglyph Attack Generator", [check it out yourself!](http://www.irongeek.com/homoglyph-attack-generator.php)
2. **Renaming:** For this part you will need to either write your own renamer using homoglyphs or modify an existing one like ConfuserEx (If I find some time ill release my version)
3. **Done :)**


I hope you enjoyed this little write up, and maybe even learned something or got inspired ^^ ~drakonia


# Credits/Sources

- [DEF CON Talk by Chris Domas](https://www.youtube.com/watch?v=HlUe0TUHOIc)
- [Punyocder](https://www.punycoder.com/) (Tool to convert homoglyphs to encoded ascii)
- [Irongeeks Homoglyph Attack Generator](http://www.irongeek.com/homoglyph-attack-generator.php)
- [Concept of Punycode](https://www.wandera.com/punycode-attacks/)


