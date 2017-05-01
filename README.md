YARA-FORENSICS
==============

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0) [![DFIR: Yara rules](https://img.shields.io/badge/DFIR-Yara%20Rules-brightgreen.svg)](https://yararules.com) [![Travis build](https://travis-ci.org/Xumeiquer/yara-forensics.svg)](https://github.com/Xumeiquer/yara-forensics)

`Yara` is the pattern matching swiss knife for malware researchers (and everyone else). Basically `Yara` allow us to scan files based on textual or binary patterns, thus we can take advantage of `Yara`'s potential and focus it in forensic investigations.

For now I have created a set of rules that search for magic headers on files and dump files like raw image of `dd` as well. So I invite anyone to add or improve rules regarding forensics stuff.

***

## Content

The repository is splitted in two folders: `file` and `raw`. The rules in `file` folder are mainly to look for `magic` in standalone files, on the other hand, rules inside `raw` folder are mainly to look for `magic` in raw file or dump files. The main difference is the offset of the magic usually at `0x0` in files.

The avaliable files are listed in [`FILES.md`](FILES.md).

***

## Yara installation

Installing `Yara` is quite easy: just follow [the official documentation](http://yara.readthedocs.io/en/v3.5.0/gettingstarted.html), after that, you can use the rules of this repository (and all `Yara` rules in general).

***

## Examples

### The basic use of `Yara` rules

This will tell whether the file `Hard_Drive.jpg` is an image.

```
$> yara file/images.yar test/Hard_Drive.jpg
jpg_magic_with_EXIF test/Hard_Drive.jpg
```

Or scanning images in dump files.

```
$> yara raw/images.yar ~/kvm/ISOs/debian-8.4.0-amd64-netinst.iso
contains_jpeg /home/xumeiquer/kvm/ISOs/debian-8.4.0-amd64-netinst.iso
```

### `Yara` options

`Yara` offers a good set of options that can be useful, as example I will show two interesting options, but there are more.

For example:

#### Offest

```
$> yara -s file/images.yar test/Hard_Drive.jpg
jpg_magic_with_EXIF test/Hard_Drive.jpg
0x0:$a: FF D8 FF E1 4B EF 45 78 69 66 00
```

This is more useful when using the raw rules.

```
$> yara -s raw/images.yar ~/kvm/ISOs/debian-8.4.0-amd64-netinst.iso
contains_jpeg /home/xumeiquer/kvm/ISOs/debian-8.4.0-amd64-netinst.iso
0x5b73800:$a: FF D8 FF E0 00 10 4A 46 49 46 00
0x5b76000:$a: FF D8 FF E0 00 10 4A 46 49 46 00
0x5b76232:$a: FF D8 FF E0 00 10 4A 46 49 46 00
```

#### Tags

It is also possible to get he rule `tags`. This will be useful when executing a bunch of rule and then filter by some possible tag.

```
yara -g file/images.yar test/Hard_Drive.jpg
jpg_magic_with_EXIF [JPG] test/Hard_Drive.jpg
```

### Benchmarks

Well, there are no actual benchmarks, but I would like to show how fast is `Yara`.

```
$> ls -lh ~/kvm/ISOs/debian-8.4.0-amd64-netinst.iso
-rw-r--r-- 1 libvirt-qemu libvirt-qemu 247M abr 22  2016 /home/xumeiquer/kvm/ISOs/debian-8.4.0-amd64-netinst.iso

$> time yara raw/images.yar ~/kvm/ISOs/debian-8.4.0-amd64-netinst.iso
contains_jpeg /home/xumeiquer/kvm/ISOs/debian-8.4.0-amd64-netinst.iso

0,72s user 0,00s system 44% cpu 0,732 total

```

```
$> ls -lh ~/kvm/ISOs/Windows\ 7\ 64Bits\ SP1.iso
-rw-r--r-- 1 libvirt-qemu libvirt-qemu 3,1G feb 17  2014 /home/xumeiquer/kvm/ISOs/Windows 7 64Bits SP1.iso

$> time yara raw/images.yar ~/kvm/ISOs/Windows\ 7\ 64Bits\ SP1.iso
contains_jpeg /home/xumeiquer/kvm/ISOs/Windows 7 64Bits SP1.iso

13,26s user 0,97s system 45% cpu 30,982 total
```

```
$> ls -lh mem.raw
-rwxr-xr-x  1 root  staff    18G 29 abr 00:18 mem.raw

$> time yara  raw/jpeg.yar mem.raw
contains_jpeg mem.raw
contains_jpg_with_EXIF mem.raw
contains_jpeg_2000 mem.raw

44,60s user 12,84s system 57% cpu 1:39,83 total
```
