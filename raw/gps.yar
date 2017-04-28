/*
    Description: This finds the magics on dump files, like raw dd image.
    Disclaimer: This can though false positives.

    Contributors:
      - Jaume Martin <@Xumeiquer>
*/

rule contains_gps: GPS GPX
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {3C 67 70 78 20 76 65 72 73 69 6F 6E 3D 22 31 2E 31}

    condition:
       $a
}
