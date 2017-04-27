/*
    Author: Joan Bono <@joan_bono>
*/

rule png_magic: PNG
{
    meta:
        author = "Joan Bono"

    strings:
        $a = {25 50 44 46}

    condition:
       $a at 0 and for any of ($b, $c, $d): (@ > @a)
}

