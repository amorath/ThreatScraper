# ThreatScraper.py - Python Script

ThreatScraper is being developed in Python to interface with VirusTotal's v2 API to search their database for a file hash (SHA256/SHA1/MD5), and if a match is found the report data is sent back to the requestor. The information sent back contains 70 different Anti Virus products, with their individual findings on the file (malicious or not), the version and date of the Anti Virus definitions, and what individual naming convention the Anti Virus service uses for the specific file requested (trojan, worm, keylogger, etc). The information is stored in an excel file, and can be scheduled to run multiple times during the day. The program is very much in development, however the ThreatScraper.py script is a working prototype.

1. Modify the script with your VirusTotal API key.

2. Enter the file hash that you would like to search for.

3. Provide the script with the excel file location to save the report.

4. Modify the scheduled times at the end, the script will execute during those times.

5. Save and close. In a command prompt, run the script with "python ThreatScraper.py".


# ThreatScraperUI.py - .exe build instructions:

Install PyInstaller: You can install PyInstaller using pip by running the following command in your terminal:

C:\ pip install pyinstaller

Create a spec file: PyInstaller requires a spec file that tells it how to build the executable. You can create a spec file by running the following command in your terminal:

C:\ pyinstaller --name ThreatScraper --onefile --windowed --icon=threatscraper.ico ThreatScraperUI.py

- This command tells PyInstaller to create a single executable file (--onefile) named ThreatScraper (--name ThreatScraper) that runs in windowed mode (--windowed) and   uses icon.ico as the application icon (--icon=threatscraper.ico).

Build the executable: Once you have a spec file, you can build the executable by running the following command in your terminal:

C:\ pyinstaller ThreatScraper.spec

This will create a dist directory containing the standalone executable for your application.

Note: Building a Python executable using pyinstaller will most likely cause it to be identified as malware. If this is the route you want to take, you may have to exclude the created file from Microsoft Defender's scans. 

https://www.techtarget.com/searchsecurity/news/252500274/Researchers-use-PyInstaller-to-create-stealth-malware

# ThreatScraper.cpp - Work in Progress

I am currently attempting to convert ThreatScraper into C++ to get around the issues that Windows Defender has with compiling Python code into executables.
