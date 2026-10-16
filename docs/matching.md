# Matching assessments to findings

`AssessmentMatcher` decides whether an assessment still covers a finding. Every consumer shares this one rule.

## When an assessment covers a finding

An assessment covers a finding only while all of these hold:

- It has not expired.
- The component still has the version the assessment names.
- The advisory still answers to one of the assessment's identities.
- For an `affected` assessment: the advisory's severity has not risen above the accepted severity.

A finding that falls out of every assessment comes back. `Resolution::$covering` tells you which assessment hid a
finding, and why.

## When several assessments cover one finding

The most alarming one decides, in this order:

1. `under_investigation`
2. `affected`
3. `fixed`
4. `not_affected`
5. `false_positive`

An `under_investigation` assessment never hides a finding.

A newer assessment does not replace an older one. The date does not matter: a later `not_affected` does not override
an earlier `under_investigation`. Retire the old assessment when you make a new one about the same advisory and
component.

## Components and versions

- A component matches only at the version written.
- Composer vendors and names are compared lowercased, as the purl specification has them.
- Versions are compared as written, so `v5.4.19` is not `5.4.19`.
- npm names keep the case they are written in, as the purl specification has them. `pkg:npm/JSONStream@1.3.5` meets
  the advisories the feeds file under `JSONStream`, is written back as such, and is not `pkg:npm/jsonstream@1.3.5`.
- A `Finding` pairs an advisory with a component of the package it is filed under. Any other pair is refused.
- The PHP runtime is `pkg:generic/php`. The purl specification registers no `php` type.

## Storing assessments

Store the identities from `AdvisoryFingerprint::identitiesOf()`, not only the canonical fingerprint. Then a CVE added
later does not detach the assessment.

Reasons are free text that someone typed. Escape them before you show them.
