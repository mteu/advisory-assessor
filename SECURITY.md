# Security Policy

Please follow the guidelines below if you believe you have discovered a
vulnerability in this project.

> [!CAUTION]
> Please do not open GitHub issues for security vulnerabilities!

## Supported Versions

While the package is in 0.x, only the latest minor release gets security
fixes. Upgrade to it to receive them.

| Version                  | Supported |
|--------------------------|-----------|
| Latest 0.x minor release | Yes       |
| Any older release        | No        |

## What to Report

Report a vulnerability in this library's own code. An assessment hides
findings, so the most likely one is an assessment that hides more than it
should. Examples are an assessment that still covers a finding after the
component's version changed, after it expired, or after an accepted
advisory was re-scored upwards. Another is a package URL that matches a
component it does not name.

A wrong claim inside an assessment belongs to whoever made it. Tell us anyway
if the library made it easy to get wrong.

## Reporting a Vulnerability

Please use GitHub's private vulnerability reporting. Open the
[Security tab](https://github.com/mteu/advisory-assessor/security) and click
"Report a vulnerability", or go straight to the
[report form](https://github.com/mteu/advisory-assessor/security/advisories/new).

Your report should include the following details:

* The exact version or version range that you analysed.
* The PHP version that you used for your analysis.
* The assessment and the finding involved, if any.
* A step-by-step explanation of how to exploit the potential vulnerability.

## What to Expect

One person maintains this project in their spare time. Expect a first reply
within 14 days. You will hear whether the report is accepted and when a fix
is planned. No bounties are offered.
