/*
    Description: This finds the magics on dump files, like raw dd image.
    Disclaimer: This can though false positives.

    Contributors:
      - Jaume Martin <@Xumeiquer>
*/

rule win_64_mem_dump: DMP
{
    meta:
        author = "Jaume Martin"
        file_info = "Windows 64-bit memory dump"

    strings:
        $a = {50 41 47 45 44 55 36 34}

    condition:
       $a
}

rule win_32_mem_dump: DMP
{
    meta:
        author = "Jaume Martin"
        file_info = "Windows 32-bit memory dump"

    strings:
        $a = {50 41 47 45 44 55 4D 50}

    condition:
       $a
}
