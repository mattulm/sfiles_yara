rule injection
{
    meta: 
    description = "Indicates attempt to inject code"
    
    strings:
    $a = "injector" fullword nocase
    $b = "injecter" fullword nocase
    $c = "injector" fullword nocase wide
    $d = "injecter" fullword nocase wide

    condition:
    any of them 
}