# CycloneDX VEX

How `CycloneDxVexWriter` and `CycloneDxVexReader` map assessments to CycloneDX and back.

## Writing

### Which assessments can be written

- The writer names a vulnerability by its CVE, else its GHSA, else the feed's own id. An assessment whose advisory
  has none of these is refused with `UnexportableAssessments`. Ask `CycloneDxVexWriter::canWrite()` first.
- Two assessments about one advisory on one component are refused with `ContradictingAssessments`, which names all of
  them. Decide which one counts before you write, for example with `AssessmentMatcher::resolve()`.

### How fields are mapped

| Assessment | CycloneDX |
| --- | --- |
| `fixed` | `resolved`. Not `resolved_with_pedigree`: the writer records no pedigree to back that claim. |
| `component_not_present` | `code_not_present` plus the property `mteu:vex:justification`, so it survives a round trip. |
| Accepted severity of an `affected` assessment | The property `mteu:vex:accepted_severity`. Without it, the assessment could not be read back. |
| Document ID | `serialNumber` |
| Document version | `version` |
| Issue time | `metadata.timestamp`. It cannot be earlier than the newest assessment written. |
| Author who is a person | `metadata.authors` |
| Author who is an organization | `metadata.manufacturer` |

Origin and expiry are never written. CycloneDX has no field for them, and an origin names people.

## Reading

An assessment hides a finding, so the reader rejects anything it cannot read with certainty. The finding stays
visible.

### Rejected and skipped entries

- One bad entry rejects the whole document. `RejectedVexEntries` names every bad entry at once: its index, its id,
  its `affects` ref and the reason.
- An entry without an analysis, or whose analysis has no state, claims nothing. It is skipped and its index is
  reported.
- Two entries about one advisory on one component are both rejected.

### Components

Each `affects` ref gives one assessment. The ref has to name a component of the same document. That component's purl
has to name one exact version of a package type `mteu/advisory-matcher` knows. BOM-Links to other documents and
version ranges are rejected.

### Identities

The identities come from `AdvisoryFingerprint::identitiesNaming()`, which spells them as `identitiesOf()` does, from
the `id` and every `references[].id`.

That reads more ids than `identitiesOf()` does. It takes a CVE only from the advisory's own CVE field, and only GHSA
ids from its references. CycloneDX defines a reference as the same vulnerability under another id, so one entry
covers each of them.

### Statuses

| CycloneDX | Assessment | Also needs |
| --- | --- | --- |
| `not_affected` | `not_affected` | A justification. The property `mteu:vex:justification` wins over `analysis.justification`. |
| `exploitable` | `affected` | A response. The first one listed is kept. |
| `resolved`, `resolved_with_pedigree` | `fixed` | Nothing more. |
| `in_triage` | `under_investigation` | Nothing, not even a `detail`. |

Every status but `in_triage` needs a non-empty `detail` as its reason.

The accepted severity of an `affected` assessment comes from the property `mteu:vex:accepted_severity`, else from the
highest of the `low`, `medium`, `high` and `critical` ratings. A rating lower than the feed's makes the assessment
stop covering the finding.

### Issue time

The issue time is `firstIssued`, else the document's `metadata.timestamp`. A time still to come is rejected: it would
push the expiry out.

### Size and speed

The reader takes the document as a string. Reading takes about as long as parsing: about 1.7 s for 4,000 entries in
1.3 MB on PHP 8.3.

Cap the size before you read it, to what your request budget allows. The parser caps the number of values, by default
at 1,000,000, not the bytes.
