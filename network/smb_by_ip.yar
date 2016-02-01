rule remote_system_syntax 
{
	meta:
		author = "@matonis"
		info = "Command syntax that is used to access remote systems by IP address"
	strings:
		$s1 = /\\\\\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
	condition:
		$s1
}
