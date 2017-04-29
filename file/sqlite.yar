/*
    Description: This finds the magics on individual files.
    Disclaimer: This can though false positives.

    Contributors:
      - Jaume Martin <@Xumeiquer>
*/

rule sqlite: SQLITE
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00}

    condition:
       $a at 0
}
