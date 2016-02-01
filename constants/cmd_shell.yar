rule cmdshell
{
	meta:
		author="@matonis"
		description="Command prompt syntax to identify potential priv escalation"
	strings:
		$cmd0 = "C:\\Documents and Settings\\Administrator"
		$cmd2 = "C:\\Users\\Administrator"
	condition:
		any of them
}