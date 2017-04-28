/*
    Description: This finds the magics on individual files.
    Disclaimer: This can though false positives.

    Contributors:
      - Jaume Martin <@Xumeiquer>
*/

rule videocd_magic: VCD
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {45 4E 54 52 59 56 43 44 02 00 00 01 02 00 18 58}

    condition:
       $a at 0
}

rule ogg_magic: OGG
{
    meta:
        author = "Jaume Martin"
        file_info = "Ogg Vorbis Codec"

    strings:
        $a = {4F 67 67 53 00 02 00 00 00 00 00 00 00 00}

    condition:
       $a at 0
}
