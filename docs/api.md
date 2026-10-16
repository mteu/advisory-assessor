# Public API

These types are the public API. Names are relative to `mteu\AdvisoryAssessor\`.

Everything else in `src/` is marked `@internal` and can change or disappear in
any release.

## Assessments

VEX and CISA call an `Assessment` a "statement". Here a `Finding` is the raw match and an `Assessment` is the judgement about it. The CycloneDX reader and writer map between the two.

- [`Assessment\Assessment`](../src/Assessment/Assessment.php): one claim about one advisory on one component at one version
- [`Assessment\Status`](../src/Assessment/Status.php): `not_affected`, `false_positive`, `affected`, `fixed` or `under_investigation`
- [`Assessment\Justification`](../src/Assessment/Justification.php): why a component is `not_affected`
- [`Assessment\Response`](../src/Assessment/Response.php): what is done about an `affected` component
- [`Assessment\Origin`](../src/Assessment/Origin.php): a user, or a pipeline and commit
- [`Assessment\OriginKind`](../src/Assessment/OriginKind.php): `user` or `pipeline`

## Matching

- [`Matching\AssessmentMatcher`](../src/Matching/AssessmentMatcher.php): decides whether an assessment still covers a finding
- [`Matching\Finding`](../src/Matching/Finding.php): an advisory on a deployed component
- [`Matching\Resolution`](../src/Matching/Resolution.php): the assessments covering a finding, and whether it is hidden

## Documents

- [`Document\VexDocumentMetadata`](../src/Document/VexDocumentMetadata.php): a VEX document's id, version, author and issue time, which the caller keeps between exports
- [`Document\Author`](../src/Document/Author.php): a person or an organization that publishes a VEX document
- [`Document\AuthorKind`](../src/Document/AuthorKind.php): `person` or `organization`

## CycloneDX

- [`CycloneDx\CycloneDxVexWriter`](../src/CycloneDx/CycloneDxVexWriter.php): writes assessments as a CycloneDX 1.6 VEX document, or one assessment as a vulnerability object; the single object is written whatever its status, without an `ExportScope`
- [`CycloneDx\ExportScope`](../src/CycloneDx/ExportScope.php): whether `affected` and `under_investigation` assessments may leave; there is no default
- [`CycloneDx\UnexportableAssessments`](../src/CycloneDx/UnexportableAssessments.php): assessments that name their advisory by no id other tools can read
- [`CycloneDx\ContradictingAssessments`](../src/CycloneDx/ContradictingAssessments.php): assessments that speak about one advisory on one component
- [`CycloneDx\CycloneDxVexReader`](../src/CycloneDx/CycloneDxVexReader.php): reads the assessments of a CycloneDX 1.4 to 1.7 VEX document, or rejects it
- [`CycloneDx\VexReading`](../src/CycloneDx/VexReading.php): the assessments read, and the entries skipped because they claim nothing
- [`CycloneDx\UnreadableVexDocument`](../src/CycloneDx/UnreadableVexDocument.php): not CycloneDX 1.4 to 1.7 JSON
- [`CycloneDx\RejectedVexEntries`](../src/CycloneDx/RejectedVexEntries.php): every entry the reader could not use, thrown once per document
- [`CycloneDx\RejectedVexEntry`](../src/CycloneDx/RejectedVexEntry.php): one entry's index, id, `affects` ref and reason
- [`CycloneDx\RejectionReason`](../src/CycloneDx/RejectionReason.php): why an entry was rejected
