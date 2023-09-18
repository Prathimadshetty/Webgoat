rules:
  - id: active-debug-code-getstacktrace
    message: Possible active debug code detected. Deploying an application with
      debug code can create unintended entry points or expose sensitive
      information.
    severity: WARNING
    metadata:
      likelihood: MEDIUM
      impact: LOW
      confidence: MEDIUM
      interfile: true
      category: security
      subcategory:
        - vuln
      cwe:
        - "CWE-489: Active Debug Code"
      owasp:
        - A10:2004 - Insecure Configuration Management
        - A06:2017 - Security Misconfiguration
        - A05:2021 - Security Misconfiguration
      references:
        - https://cwe.mitre.org/data/definitions/489.html
        - https://www.acunetix.com/vulnerabilities/web/stack-trace-disclosure-java/
        - https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/02-Testing_for_Stack_Traces
        - https://www.securecodewarrior.com/blog/coders-conquer-security-share-learn-series-information-exposure
      technology:
        - java
      license: Copyright 2023 Semgrep, Inc.
      vulnerability_class:
        - Active Debug Code
    languages:
      - java
    mode: taint
    pattern-sources:
      - pattern: $EXCEPTION.getStackTrace()
      - pattern: $UTIL.getStackTrace(...)
      - pattern: $EXCEPTION.getFullStackTrace(...)
    pattern-sinks:
      - pattern: $SYSTEM.println(...)
      - pattern: $SYSTEM.print(...)
      - pattern: $SYSTEM.format(...)
