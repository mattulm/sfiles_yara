# sigs

So far this is just a collection of YARA signatures I found on the web, through various sources. I have tried to deduplicate as much as possible, but there could be a few that I have missed. Also, I have tried to make sure that no private, or commercial rules have been included in this listing. These should all be Open Source and available to all.

I have given credit to the authors where and when I have it. If there is a rule of yours that you wish to not be included in this repository, please let me know, and I will remove it. If you have some rules that you would like included in this repository;
	1. first, thank you!!!
	2. I will add them, once I have been able to test, and verify it works and is not a duplicate of previous included rules.
	

Currently in the collection:
	android 	- Many of these require the androguard module. These haev been placed in a seperate folder.
	constants 	- A collection of signatures to detect specific constants. These could include file types, crypto 
				  signatures, types of packers and compilers, debugging, sandboxes, etc.
	linux		- Not too many of these, but I have included what I have been able to find.
	mac			- Not too many of these, but I have included what I have been able to find.
	network 	- For now, this is various signatures to detect specific types of network activity not related to malware. 
				  Dynamic DNS domains are included in here. A few signatures based on generic network activity as well.
	