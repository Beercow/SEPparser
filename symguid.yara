rule symguid
{
    strings:
        $hex1 = {2B5CA624B61E3F408B994BF679001DC2}
        $hex2 = {334FC1F5F2DA574E9BE8A16049417506}
        $hex3 = {38ACED4CA8B2134D83ED4D35F94338BD}
        $hex4 = {5E6E81A4A77338449805BB2B7AB12FB4}
        $hex5 = {6AB68FC93C09E744B828A598179EFC83}
        $hex6 = {95AAE6FD76558D439889B9D02BE0B850}
        $hex7 = {8EF95B94E971E842BAC952B02E79FB74}
        $hex8 = {a72bbcc1e52a39418b8bb591bdd9ae76}
        $hex9 = {6A007A980A5B0A48BDFC4D887AEACAB0}
        $hex10 = {d40650bd02fde745889cb15f0693c770}
        $hex11 = {ca 5b 3a 09 0e 75 1a 9e de 9d a4 4d 8a c8 b5 9c}
        $hex12 = {32 16 14 4c}
        $hex13 = {f2ecb3f7d763ae4db49322cf763fc270}
        $hex14 = {3dc1b6debae889458213d8b252c465fc}
    condition:
        any of them
}