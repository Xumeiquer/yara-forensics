rule dex : DEX Dalvik
{
    meta:
        reference = "https://source.android.com/devices/tech/dalvik/dex-format#dex-file-magic"
    condition:
        uint32(0) == 0x0a786564
}
