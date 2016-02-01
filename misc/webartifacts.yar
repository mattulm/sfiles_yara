rule webartifact_html
{
	meta:
		author="@matonis"
		description="HTML identifiers"
	strings:
		//sepcific tags
		$html0 = "DOCTYPE"
		$html1 = "head>"
		$html2 = "body>"
		$html3 = "title>"
		$html4 = "body>"
		$html5 = "html>"
		$html6 = "</html>"
		$html7 = "<!--"
		$html8 = "-->"
		$html9 = "br>"
		$html10 = "script>"

	condition:
		2 of them
}

rule webartifact_javascript
{
	meta:
		author="@matonis"
		description="Javascript signature"
	strings:
		$java0 = "document.write" nocase
		$java1 = "createElement" nocase
		$java2 = "getElementsByTagName" nocase
		$java3 = "appendChild" nocase
		$java4 = "eval" nocase
		$java5 = "document.cookie" nocase
		$java6 = "p,a,c,k,e,d" nocase
		$java7 = ".substring"
	condition:
		3 of them
}

rule webartifact_gmail
{
	meta:
		author="@matonis"
		description="Gmail artifacts"
	strings:
		$s1 = "[\"ms\","
		$s2 = "[\"ce\"]"
		$s3 = "[\"e\""
	condition:
		2 of them
}