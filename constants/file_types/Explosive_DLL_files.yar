import "pe"

rule explosive_dll {
	meta:
		author = "Checkpoint Software Technologies inc."
		info = "Explosive DLL"
	
	condition:
		pe.DLL
		and ( pe.exports("PathProcess") or pe.exports("_PathProcess@4") )
		and pe.exports ("CON")
}

rule explosive_1
{
meta:
	author = "Checkpoint Software Technologies inc."
	info = "Explosive DLL"
strings:
	$MZ = "MZ"
	$DLD_S = "DLD-S:"
	$DLD_E = "DLD-E:"
condition:
	$MZ at 0 and all of them
}
