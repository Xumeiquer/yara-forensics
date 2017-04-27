/*
    Author: Joan Bono <@joan_bono>
*/

rule png_magic: PNG
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 89 50 4E 47 0D 0A 1A 0A }

    condition:
       $a at 0
}

