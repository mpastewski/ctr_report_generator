# IMPORTANT

This is purely entusiastical project that is not under Cisco support.

# General

This project aims to provide reporting capabilities for Cisco CTR (Cyber Threat Response). It leverages APIs to connect to CTR in order to gather logs presented in report. For now reports are generated as PDF files

## Getting Started

* Edit ctr_report_generator.py file to insert API keys of the solutions:
```
AMP_CLIENT_ID = ""
AMP_API_KEY = ""
CTR_USER = ''
CTR_PASSWORD = ''
```

* Run main script:
```
python ctr_report_generator.py
```

* Run report script:
```
python report.py
```

* Report will be generated in the directory with scripts

