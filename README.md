# ThreatScraper

ThreatScraperEdit is a Python-based tool designed to check virus information by using VirusTotal API. It offers functionalities such as scheduling the checking at specific times, showing and saving the graph of malware detection trends, as well as saving virus information to an Excel file.

This version of ThreatScraper has been enhanced to use `poetry` for dependency management, and to use `black` and `isort` for code formatting.

## Prerequisites

Before you begin, ensure you have installed:

- Python 3.8 or higher
- Poetry package manager

## Installing ThreatScraperEdit

To install ThreatScraperEdit and its dependencies, follow these steps:

1. Clone the repository:
```bash
git clone https://github.com/your_username/ThreatScraper.git
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

## License

This project uses the following license: [Add License here]

## Contact

If you want to contact me you can reach me at [Your Email or social media handle].