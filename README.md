# VulnerableCode

[![Build Status](https://travis-ci.org/nexB/vulnerablecode.svg?branch=develop)](https://travis-ci.org/nexB/vulnerablecode)

Setup
-----
VulnerableCode requires Python 3.6+, get the latest version at https://www.python.org/

Clone the source code:

```
git clone https://github.com/nexB/vulnerablecode.git && cd vulnerablecode
```

Activate a virtualenv and install dependencies:

```
python3.6 -m venv .
source bin/activate
pip install -r requirements.txt
```

Tests
-----

```
pycodestyle --exclude=migrations,settings.py,lib --max-line-length=100 .
python3.6 -m pytest -v tests/
```

Scrape
------

```
from scraper import debian, ubuntu

debian.scrape_cves()
ubuntu.scrape_cves()
```