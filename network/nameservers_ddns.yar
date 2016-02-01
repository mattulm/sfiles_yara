rule dyndns_nameservers_1 { 

	meta:
		author: 	Matthew Ulm //@mattulm
		descip:		List of Dynamic DNS domains as I discover them.
		
	strings:
		$001 = "nf1.no-ip.com"
		$002 = "nf2.no-ip.com"
		$003 = "nf3.no-ip.com"
		$004 = "nf4.no-ip.com"
		$005 = "nf5.no-ip.com"
		$006 = "ns0.dnsdynamic.org"
		$007 = "ns1.afraid.org"
		$008 = "ns1.chickenkiller.com"
		$009 = "ns1.dnsdynamic.org"
		$010 = "ns1.duiadns.net"
		$011 = "ns1.dyndns.org"
		$012 = "ns2.afraid.org"
		$013 = "ns2.dnsdynamic.org"
		$014 = "ns2.duiadns.net"
		$015 = "ns2.dyndns.org"
		$016 = "ns3.afraid.org"
		$017 = "ns3.dyndns.org"
		$018 = "ns4.afraid.org"
		$019 = "ns4.dyndns.org"
		$020 = "ns5.dyndns.org"
		$021 = "ns1.duckdns.org"

	condition: 
		any of them 
}