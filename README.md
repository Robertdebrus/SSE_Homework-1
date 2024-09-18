
Here's a blank template for you to use.

## Getting Started 
---

To get a local copy up and running follow these simple example steps.

### Running the program

1. Get a free API Key at [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) 
2. Install dependencies
     ```pip3 install -r requirements.txt```
3. Enter your API in `config.py`
   ```API_KEY = 'ENTER YOUR API'```
4. Run ```python3 main.py doAll pom.xml``` to reset and download database, or ```detectOnly``` to leave the database as-is. ```pom.xml``` should be replaced with your test file.
5. Get results! For example: 
```
$ python3 main.py detectOnly pom-3.xml 
Known security vulnerabilities detected:

Dependency: htmlunit
Version(s): >= 0.0 < 2.61.0
Vulnerabilities:
- CVE-2022-29546 (High Severity)

Dependency: htmlunit
Version(s): >= 0.0 < 3.0.0
Vulnerabilities:
- CVE-2023-26119 (Critical Severity)

Dependency: htmlunit
Version(s): >= 0.0 < 2.70.0
Vulnerabilities:
- CVE-2023-2798 (High Severity)

Dependency: htmlunit
Version(s): >= 0.0 < 3.9.0
Vulnerabilities:
- CVE-2023-49093 (High Severity)
```