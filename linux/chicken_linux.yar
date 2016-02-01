rule chicken_dos_linux {
  meta:
    author = "Jason Jones <jasonjones@arbor.net>"
    description= "Linux-variant of Chicken ident for both dropper and dropped file"
  strings:
    $cfg = "fake.cfg"
    $file1 = "ThreadAttack.cpp"
    $file2 = "Fake.cpp"
    $str1 = "dns_array"
    $str2 = "DomainRandEx"
    $str3 = "cpu %llu %llu %llu %llu"
    $str4 = "[ %02d.%02d %02d:%02d:%02d.%03ld ] [%lu] [%s] %s" ascii
  condition:
    $cfg and all of ($file*) and 3 of ($str*)
}
