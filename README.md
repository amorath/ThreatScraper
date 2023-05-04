# ThreatScraper

ThreatScraper is being developed in Python to interface with VirusTotal's v2 API to search their database for a file hash (SHA256/SHA1/MD5), and if a match is found the report data is sent back to the requestor. The information sent back contains 70 different Anti Virus products, with their individual findings on the file (malicious or not), the version and date of the Anti Virus definitions, and what individual naming convention the Anti Virus service uses for the specific file requested (trojan, worm, keylogger, etc). The information is stored in an excel file, and can be scheduled to run multiple times during the day.

Modify the script with your VirusTotal API key.

Enter the file hash that you would like to search for.

Provide the script with the excel file location to save the report.

Modify the scheduled times at the end, the script will execute during those times.

Save and close. In a command prompt, run the script with "python ThreatScraper.py".
