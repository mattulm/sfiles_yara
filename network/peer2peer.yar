rule peertopeer
{
    meta:
    description = "Indicates P2P file sharing attempts"
    
	strings:
	$ptp1 = "BearShare" nocase
	$ptp2 = "iMesh" nocase fullword
	$ptp3 = "Shareaza" nocase
	$ptp4 = "Kazaa" nocase
	$ptp5 = "DC++" nocase
	$ptp6 = "eMule" nocase
	$ptp7 = "LimeWire" nocase

	condition:
	any of them
}