/*
    Description: This finds the magics on dump files, like raw dd image.
    Disclaimer: This can though false positives.

    Contributors:
      - Jaume Martin <@Xumeiquer>
*/

rule contains_ogg: OGG
{
    meta:
        author = "Jaume Martin"
        file_info = "Ogg Vorbis Codec"

    strings:
        $a = {4F 67 67 53 00 02 00 00 00 00 00 00 00 00}

    condition:
       $a
}
