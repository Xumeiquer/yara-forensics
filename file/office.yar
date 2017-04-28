/*
    Author: Jaume Martin
    Date: 24/04/2017
    Description: This finds the magics on individual files.
*/

rule doc_magic: DOC
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {CF 11 E0 A1 B1 1A E1 00}

    condition:
       $a at 0
}

rule excel_2007_magic: XLSX
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 50 4b 03 04 }

    condition:
       $a at 0
}

rule excel_2003_magic: XLS
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { D0 CF 11 E0 A1 B1 1A E1 00 }

    condition:
       $a at 0
}

rule excel_XML_magic: XLS
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 3C 3F 78 6D 6C 20 76 }

    condition:
       $a at 0
}

rule excel_OS2worksheet_magic: XLS
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 09 00 04 00 06 00 }

    condition:
       $a at 0
}

rule excel_OrthoTrack_magic: XLS
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 56 65 72 73 69 6F 6E 09 }

    condition:
       $a at 0
}

