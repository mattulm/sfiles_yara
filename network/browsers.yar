rule browsers
{
    meta:
    description = "Indicates attempt to modify browser behavior"
    
    strings:
    $browser0 = "browser" nocase
    $browser1 = "avant" nocase
    $browser2 = "netscape" nocase fullword
    $browser3 = "flock" nocase
    $browser4 = "safari" nocase 
    $browser5 = "chrome" nocase
    $browser6 = "opera" nocase fullword
    $browser7 = "mozilla" nocase
    $browser8 = "firefox" nocase
    $browser9 = "GreenBrowser" fullword
    
    $adobe1 = "Adobe Systems Incorporated" 
    $adobe2 = "Adobe Systems Incorporated" wide
    
    condition:
    (4 of ($browser*)) and not $adobe1 and not $adobe2
}