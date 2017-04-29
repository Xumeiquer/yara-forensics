/*
    Description: This finds the magics on individual files.
    Disclaimer: This can though false positives.

    Contributors:
      - Jaume Martin <@Xumeiquer>
*/

rule _7z: _7z
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {37 7A BC AF 27 1C}

    condition:
       $a at 0
}
