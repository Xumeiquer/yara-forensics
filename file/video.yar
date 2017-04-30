/*
    Description: This finds the magics on individual files.
    Disclaimer: This can though false positives.

    Contributors:
      - Jaume Martin <@Xumeiquer>
      - Joan Bono <@joan_bono>
*/

rule videocd: VCD
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {45 4E 54 52 59 56 43 44 02 00 00 01 02 00 18 58}

    condition:
       $a at 0
}

rule ogg: OGG
{
    meta:
        author = "Jaume Martin"
        file_info = "Ogg Vorbis Codec"

    strings:
        $a = {4F 67 67 53 00 02 00 00 00 00 00 00 00 00}

    condition:
       $a at 0
}

rule avi: AVI
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 52 49 46 46 }

    condition:
       $a at 0
}

rule mkv: MKV
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 1A 45 DF A3 }

    condition:
       $a at 0
}

rule flv: FLV
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 46 4C 56 01 }

    condition:
       $a at 0
}

