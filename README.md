# ThreatScraper

ThreatScraper is a Python-based tool designed to check virus information by using VirusTotal API. It offers functionalities such as scheduling the checking at specific times, showing and saving the graph of malware detection trends, as well as saving virus information to an Excel file. The Excel file "Toxicember.xlsx" is an example file that can be used to test the program, and also to show how a typical scheduled report will be displayed.

This version of ThreatScraper has been enhanced to use `poetry` for dependency management, and to use `black` and `isort` for code formatting.

## Prerequisites

Before you begin, ensure you have installed:

- Python 3.8 or higher
- Poetry package manager

## Installing ThreatScraperEdit

To install ThreatScraperEdit and its dependencies, follow these steps:

1. Clone the repository:
```bash
git clone https://github.com/amorath/ThreatScraper.git
```

2. Navigate to the ThreatScraperEdit directory:
```bash
cd ThreatScraper
```

3. Install the dependencies:
```bash
poetry install
```

## Running ThreatScraper

To run ThreatScraper. 

```bash
poetry run python main.py
```

## Code formatting with Black and Isort

Before committing new changes, ensure your Python code is correctly formatted by running:

```bash
poetry run black .
poetry run isort .
```

# ThreatScraper.py - Python Script

ThreatScraper is being developed in Python to interface with VirusTotal's v2 API to search their database for a file hash (SHA256/SHA1/MD5), and if a match is found the report data is sent back to the requestor. The information sent back contains 70 different Anti Virus products, with their individual findings on the file (malicious or not), the version and date of the Anti Virus definitions, and what individual naming convention the Anti Virus service uses for the specific file requested (trojan, worm, keylogger, etc). The information is stored in an excel file, and can be scheduled to run multiple times during the day. The program is very much in development, however the ThreatScraper.py script is a working prototype.

1. Modify the script with your VirusTotal API key.

2. Enter the file hash that you would like to search for.

3. Provide the script with the excel file location to save the report.

4. Modify the scheduled times at the end, the script will execute during those times.

5. Save and close. In a command prompt, run the script with "python ThreatScraper.py".

## License

This project uses the following license:

MIT License

Copyright (c) 2023 amorath

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


## Contact

If you want to contact me you can reach me at threatscraper@gmail.com
