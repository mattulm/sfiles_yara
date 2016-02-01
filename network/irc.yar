rule irc
{
	meta:
		author="@matonis"
		description="IRC Artifacts"
	strings:
		$irc0="has joined #"
		$irc1 = "Channel created on"
		$irc2 = "USER"
		$irc3 = "PASS"
		$irc5 = "NICK"
		$irc6 = "CHANNEL"
		$irc7 = /are [0-9]* users and [0-9]* invisible on/
		$irc8 = /[0-9]* operator(s) online/

	condition:
		$irc0 or ($irc2 and $irc3 and $irc5 and $irc6) or $irc7 or $irc8 or $irc1
}

rule ircdetection
{
    meta:
    description = "Indicates use of IRC"
    
    strings:
    $irc0 = "join" nocase fullword
    $irc1 = "msg" nocase fullword
    $irc2 = "nick" nocase fullword
    $irc3 = "notice" nocase fullword
    $irc4 = "part" nocase fullword
    $irc5 = "ping" nocase fullword
    $irc6 = "quit" nocase fullword
    $irc7 = "chat" nocase fullword
    $irc8 = "privmsg" nocase fullword
    
    condition:
    4 of ($irc*)
} 