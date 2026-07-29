- [Encoding](#encoding)
- [Representation of Characters](#representation)
   - [ASCII](#ascii)
      - [Why ASCII failed?](#why-ascii-failed)
   - [Unicode](#unicode)
      - [UTF-8](#utf8)
- [Policy Flow](#policy-flow)
   - [Issues](#issues)
      - [Problematic Policy Engine Code](#problematic-code)
   - [Fixed UTF-8](#fixed-utf8)
      - [Fixed policy engine code](#fixed-code)
         - [UTF-8 encoding rules](#utf8-rules)

<a name=encoding></a>

## Encoding
- Encoding means how policies are stored in json at UI and how those are read in policy engine.

<a name=representation></a>

## Representation of Characters

<a name=ascii></a>

### 1. ASCII
Only stores every character on 1 byte. Total 128 characters, eg(A -> 65, B -> 66, C -> 67) 
```
1..127
A-Z
a-z
0-9
special characters
```

<a name=why-ascii-failed></a>

#### Why ASCII failed?
- ASCII internal representation can only store English. Since it gives 1 byte to 1 character. 
- It cannot support languages(eg: Chinese,Hindi,Japanese or any language) whose characters are represented by multibyte characters.
```
A -> 1 byte
中 -> 3 bytes
😊 -> 4 bytes (multibyte character)  // No representation in ASCII
```

<a name=unicode></a>

### 2. Unicode
- Similar to ascii, this is a representation which maps all character(letters, symbols, emojis) present till date to a unique number called a code point. Total Characters=Over 1.4Million+
```
Dec   Hex	    UTF-8Hex Char
0     U+0000	00        0
10    U+000A	0A        Line Feed (lf)
65	  U+0041	41	      A
97	  U+0061	61	      a
      U+4E2D  E4B8AD    中
      U+1F60A           😊
```

<a name=utf8></a>

#### UTF-8
- UTF-8 is way of Storing Unicode characters in memory. UTF-8 assigns 1-4 bytes for every character.
```
A     1 byte
中    3 bytes
😊    4 bytes

Hello   5 bytes
中中    6 bytes
```

<a name=policy-flow></a>

## Policy Flow

<a name=issues></a>

### Issues
```
UI sending JSON (UTF-16)              // 1. UI was sending UTF-16
{
    "policyName": "Allow_日本😊"
}
   │
   ▼
HTTP Server
   │
   ▼
dpmgmtsvc                             // 2. Doing normalization
A converted to a
"policyName": "allow_日本😊"
   │
   ▼
JSON Parser
   │
   ▼
policy engine                       // 3. Reading/Manipulating as string
```

<a name=problematic-code></a>

#### Problematic Policy Engine Code
```cpp
int main() {
  string policyName = "A本😊";            //3 characters
  cout << policyName.size() << endl;      //8 bytes. A(1 byte),本(3 bytes), 😊(4 bytes)
  
  // Wrong output. Expecting 3rd character😊
  // it prints 3rd byte
  cout << policyName[3] << endl;          //�
}
```

<a name=fixed-utf8></a>

### Fixed UTF-8
```
UI sending JSON (UTF-8)              // 1. UI sends UTF-8
{
    "policyName": "Allow_日本😊"
}
   │
   ▼
HTTP Server
   │
   ▼
dpmgmtsvc                             // 2. Does not normalize
"policyName": "allow_日本😊"
   │
   ▼
JSON Parser
   │
   ▼
policy engine                       // 3. read using UTF-8 encoding rules 
```

<a name=fixed-code></a>

#### Fixed policy engine code

<a name=utf8-rules></a>

##### UTF-8 encoding rule:
- Read the first byte.
- Look at the starting bits. 110xxxxx(2byte character), 1110xxxx(3byte character), 11110xxx(4byte character)

**Logic to identify 2byte,3byte or 4byte UTF-8 Character**

- **2 byte UTF-8:** All 2 byte characters in UTF-8 has this pattern(110xxxxx). if AND with 11100000 and it returns 1100 0000, then its 2 byte
```
   é = C3 = 1100 0011
          & 1110 0000
         -------------
            1100 0000      
```
- **3 byte UTF-8:** All 2 byte characters in UTF-8 has this pattern(1110xxxx). if AND with 11110000 and it returns 1110 0000, then its 3 byte
```
   日 = E6 97 A5 
   E6 = 1110 0110
      & 1111 0000
      -------------
        1110 0000
```
- **4 byte UTF-8:** All 2 byte characters in UTF-8 has this pattern(11110xxx). if AND with 11111000 and it returns 1111 0000, then its 4 byte
```
   😊 = F0 9F 98 8A 
   F0  = 1111 0000
      &  1111 1000
      -------------
         1111 0000
```

**C Code**
```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>

int Identify_UTF_Character(unsigned char c)
{
    if ((c & 0x80) == 0)               // ASCII: 0xxxxxxx
        return 1;       

    else if ((c & 0xE0) == 0xC0)       // 2 byte UTF-8 character 110xxxxx
        return 2; 

    else if ((c & 0xF0) == 0xE0)      // 3 byte UTF-8 character 1110xxxx
        return 3; 

    else if ((c & 0xF8) == 0xF0)      // 4 byte UTF-8 character 11110xxx
        return 4;

    return -1;          // invalid UTF-8
}


// Decode UTF-8 character into Unicode code point
uint32_t decode_utf8(const unsigned char *s, int *bytes)
{
    uint32_t codepoint;
    int len = Identify_UTF_Character(s[0]);
    *bytes = len;
    if (len == 1) {
        return s[0];
    }

    if (len == 2){
        codepoint =
            ((s[0] & 0x1F) << 6) |
            (s[1] & 0x3F);
        return codepoint;
    }

    if (len == 3){
        codepoint =
            ((s[0] & 0x0F) << 12) |
            ((s[1] & 0x3F) << 6) |
            (s[2] & 0x3F);
        return codepoint;
    }


    if (len == 4) {
        codepoint =
            ((s[0] & 0x07) << 18) |
            ((s[1] & 0x3F) << 12) |
            ((s[2] & 0x3F) << 6) |
            (s[3] & 0x3F);
        return codepoint;
    }
    return 0;
}

int main()
{
    char policyName[] = u8"Allow_日本😊";
    unsigned char *ptr = (unsigned char *)policyName;
    int character = 1;

    while (*ptr)
    {
        int bytes;

        uint32_t codepoint = decode_utf8(ptr, &bytes);
        printf("Character %d: ", character);
        printf("UTF-8 bytes: ");
        for (int i=0;i<bytes;i++) {
            printf("%02X ", ptr[i]);
        }
        printf(" Codepoint: U+%04X\n", codepoint);
        ptr += bytes;
        character++;
    }
    return 0;
}
```

**CPP 20**
```cpp
#include <iostream>
#include <string>
#include <locale>
#include <codecvt>      //for turning text strings into different character formats.

int main()
{
    string policyName = u8"A本😊";
    wstring_convert<std::codecvt_utf8<char32_t>, char32_t> converter;

    u32string unicode = converter.from_bytes(policyName);
    std::cout << "Characters: " << unicode.size() << std::endl;
    char32_t ninth = unicode[3];
    std::wstring_convert<std::codecvt_utf8<char32_t>, char32_t> out;
    std::cout << out.to_bytes(ninth) << std::endl;
}
```
