rule administrative_share_abuse
{
    meta:
		author="@matonis"
        description="syntax for accessing adminstrative shares"
	strings:
		$s0 = /(copy|del|psexec|net)/ nocase
        $s1 = "\\c$\\windows\\system32\\" nocase
        $s2 = "\\c$\\system32\\" nocase
        $s3 = "\\admin$\\" nocase
	condition:
		$s0 and (any of ($s1,$s2,$s3))
}