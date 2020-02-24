/*
    Description: This finds the magics on individual files.
    Disclaimer: This can though false positives.

    Contributors:
      - Jaume Martin <@Xumeiquer>
*/

rule telegram_file: telegram
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {54 44 46 24}

    condition:
       $a
}

rule telegram_encrypted_file: telegram
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {54 44 45 46}

    condition:
       $a
}
