rule social_security_syntax
{
	meta:
		author="@matonis"
		description="SSN Syntax"
	strings:
		$s1 = /[0-9]{3}-[0-9]{2}-[0-9]{3}/
	condition:
		$s1
}