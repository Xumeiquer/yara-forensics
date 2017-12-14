/*
    Description: This finds the magics on individual files.
    Disclaimer: This can though false positives.

    Contributors:
      - Joan Bono <@joan_bono>
*/

rule exe: EXE
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 4D 5A }
	$b = "!This program cannot be run in DOS mode."

    condition:
       $a at 0 and $b
}

//test

rule elf32: ELF32
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 62 70 6c 69 73 74 30 30 }

    condition:
       $a at 0
}

rule elf64: ELF64
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 62 70 6c 69 73 74 30 30 }

    condition:
       $a at 0
}

rule macho: MACHO
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 62 70 6c 69 73 74 30 30 }

    condition:
       $a at 0
}


