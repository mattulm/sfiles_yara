rule smtp
{
	meta:
		author="@matonis"
		description="SMTP Artifacts"
		
	strings:
		$stmp0 = "HELO"
		$stmp1 = "MAIL FROM"
		$stmp2 = "RCPT TO"
		$stmp4 = "From:"
		$stmp5 = "To:"
		$stmp6 = "Cc:"
		$stmp7 = "Date:"
		$stmp8 = "Subject:"
		$stmp9 = "Delivered-To:"
		$stmp10 = "Received: by"
		$stmp11 = "Authentication-Results:"
		$stmp12 = "Return-Path:"
		$stmp13 = "Message-ID:"
		$stmp14 = "Content-Transfer-Encoding:"
		$stmp15 = "Content-Disposition:"
		$stmp16 = "X-Forwarded-To:"
		$stmp17 = "X-Forwarded-For:"
	condition:
		7 of them
}