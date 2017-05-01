/*
    Description: This finds the magics on dump files, like raw dd image.
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
       $a
}

rule ogg: OGG
{
    meta:
        author = "Jaume Martin"
        file_info = "Ogg Vorbis Codec"

    strings:
        $a = {4F 67 67 53 00 02 00 00 00 00 00 00 00 00}

    condition:
       $a
}

rule avi: AVI
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 52 49 46 46 }

    condition:
       $a
}

rule mkv: MKV
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 1A 45 DF A3 }

    condition:
       $a
}

rule flv: FLV
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 46 4C 56 01 }

    condition:
       $a
}

rule wmv: WMV
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 30 26 B2 75 8E 66 CF 11 A6 D9 00 AA 00 62 CE 6C }

    condition:
       $a 
}

rule mpg2: MPG
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 00 00 01 BA 44 }

    condition:
       $a 
}

rule mpg4: MP4
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 00 00 00 14 66 74 79 70 69 73 6F 6D 00 00 00 01 }

    condition:
       $a 
}

rule mov: MOV
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 4B 41 4D 76 }

    condition:
       $a 
}

rule real_media_stream: RM
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 2E 52 4D 46 00 00 00 12 00 }

    condition:
       $a 
}

rule raw_h264: H264
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 00 00 00 01 67 64 00 1F AC 34 E2 40 B4 11 7E E1 }

    condition:
       $a 
}

rule magic_lantern_video: MLV
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 4D 4C 56 49 }

    condition:
       $a 
}

