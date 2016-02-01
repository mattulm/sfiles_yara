rule encoding 
{ 
    meta: 
    description = "Indicates encryption/compression"
    
    strings:
    $zlib0 = "deflate" fullword
    $zlib1 = "Jean-loup Gailly"
    $zlib2 = "inflate" fullword
    $zlib3 = "Mark Adler"
    
    $ssl0 = "OpenSSL" fullword
    $ssl1 = "SSLeay" fullword
    
    condition:
    (all of ($zlib*)) or (all of ($ssl*))
}