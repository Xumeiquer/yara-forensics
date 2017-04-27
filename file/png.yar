/*
    Author: Joan Bono <@joan_bono>
*/

rule png_magic: PNG
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 89 50 4E 47 0D 0A 1A 0A }
	$b = { 49 48 44 52 }
	$c = { 49 44 41 54 }
	$d = { 49 45 4E 44 }

    condition:
       $a at 0 and for any of ($b, $c): (@ > @a) and $d
}

