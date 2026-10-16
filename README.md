<div align="center">

[![CGL](https://github.com/mteu/advisory-assessor/actions/workflows/cgl.yaml/badge.svg)](https://github.com/mteu/advisory-assessor/actions/workflows/cgl.yaml)
[![Tests](https://github.com/mteu/advisory-assessor/actions/workflows/tests.yaml/badge.svg?branch=main)](https://github.com/mteu/advisory-assessor/actions/workflows/tests.yaml)
[![PHP Version Require](https://poser.pugx.org/mteu/advisory-assessor/require/php)](https://packagist.org/packages/mteu/advisory-assessor)

# Advisory Assessor

</div>

PHP library that records what a developer found after looking at an advisory match
(e.g. through [`mteu/advisory-matcher`](https://github.com/mteu/advisory-matcher)),
as an exportable **Vulnerability Exploitability eXchange (VEX)** statement, and
decides which findings an assessment still covers. This library holds the answer
you give back to that advisory: not affected, a false positive, affected and
accepted, fixed, or under investigation.

> [!WARNING]
> This project is not yet intended for production use. The API may change
> without notice.

## 🚀 Features

* Assessments in the VEX sense, with CycloneDX's justification vocabulary. Each assessment carries what CISA's
  [Minimum Requirements for VEX](https://www.cisa.gov/resources-tools/resources/minimum-requirements-vulnerability-exploitability-exchange-vex)
  ask of a statement, and each written document what they ask of a document: an ID, a version, an author and an
  issue time.
* One rule for whether an assessment still covers a finding, shared by every consumer: `AssessmentMatcher::resolve()`
  for a finding and every assessment, `AssessmentMatcher::covers()` for one pair
* Components named by [package URL](https://github.com/package-url/purl-spec) at one exact version, as the
  matcher's `PackageRef`, so an advisory and a component name a package the same way
* CycloneDX 1.6 VEX documents, written from their input alone and in a stable order, so they diff cleanly in a
  repository
* One assessment as a CycloneDX vulnerability object, to paste into a VEX a project keeps in its repository
* CycloneDX 1.4 to 1.7 VEX documents read back into assessments, parsed with
  [`mteu/sbom-parser`](https://github.com/mteu/sbom-parser). If any entry is unclear, the whole document is rejected
  and every bad entry is named with a `RejectionReason`.

> [!NOTE]
> What VEX and CISA call a "statement" is an `Assessment` in this library. A `Finding` is the raw advisory match, and an
> `Assessment` is what a person concludes about it. The CycloneDX reader and writer map between the two.

## ⚡️ Installation

```bash
composer require mteu/advisory-assessor
```

You also need a PSR-20 clock implementation, such as `symfony/clock`.

## 💡 Usage

```php
use mteu\AdvisoryAssessor\Matching\Finding;
use mteu\AdvisoryAssessor\Matching\AssessmentMatcher;
use mteu\AdvisoryAssessor\Assessment\Justification;
use mteu\AdvisoryAssessor\Assessment\Origin;
use mteu\AdvisoryAssessor\Assessment\Assessment;
use mteu\AdvisoryAssessor\Assessment\Status;
use mteu\AdvisoryMatcher\Advisory\AdvisoryFingerprint;
use mteu\AdvisoryMatcher\Source\PackageRef;

// $advisory: mteu\AdvisoryMatcher\Advisory\Advisory, from the matcher
// $clock: Psr\Clock\ClockInterface
$component = PackageRef::fromString('pkg:composer/symfony/http-kernel@5.4.19');

$assessment = new Assessment(
    identities: AdvisoryFingerprint::identitiesOf($advisory),
    component: $component,
    status: Status::NotAffected,
    reason: 'We never render fragments, so the vulnerable path is never called.',
    origin: Origin::user('42'),
    issuedAt: $clock->now(),
    justification: Justification::CodeNotReachable,
);

$resolution = (new AssessmentMatcher($clock))->resolve(new Finding($advisory, $component), [$assessment]);

if ($resolution->isHidden()) {
    printf("hidden by a %s assessment\n", $resolution->covering[0]->status->value);
}
```

<details>
<summary><strong>Writing CycloneDX VEX</strong></summary>

```php
use mteu\AdvisoryAssessor\CycloneDx\CycloneDxVexWriter;
use mteu\AdvisoryAssessor\CycloneDx\ExportScope;
use mteu\AdvisoryAssessor\Document\Author;
use mteu\AdvisoryAssessor\Document\VexDocumentMetadata;

// Keep the document ID for the life of the document. Raise the version and
// renew the issue time whenever its content changes.
$document = new VexDocumentMetadata(
    documentId: '3e671687-395b-41f5-a30f-a58921a69b79',
    version: 4,
    author: Author::organization('Acme Security Team'),
    issuedAt: $clock->now(),
);

// ExportScope::All also writes affected and under_investigation assessments.
// They list known, unfixed vulnerabilities, so think twice before using it.
$json = (new CycloneDxVexWriter())->write($assessments, ExportScope::ResolvedOnly, $document);
```

</details>

<details>
<summary><strong>Reading CycloneDX VEX</strong></summary>

```php
use mteu\AdvisoryAssessor\CycloneDx\CycloneDxVexReader;
use mteu\AdvisoryAssessor\CycloneDx\RejectedVexEntries;
use mteu\AdvisoryAssessor\CycloneDx\UnreadableVexDocument;
use mteu\AdvisoryAssessor\Assessment\Origin;
use mteu\SbomParser\Parser\CycloneDxParser;

$reader = new CycloneDxVexReader(new CycloneDxParser(), $clock);

try {
    // CycloneDX names neither who made an assessment nor when it expires, so you say.
    $reading = $reader->read($json, Origin::pipeline('acme/shop', $commit), new \DateInterval('P90D'));
} catch (UnreadableVexDocument) {
    // Not CycloneDX 1.4 to 1.7 JSON.
} catch (RejectedVexEntries $rejection) {
    foreach ($rejection->entries as $entry) {
        // $entry->index, $entry->vulnerabilityId, $entry->ref and $entry->reason.
        // The id and the ref come from the document: escape them.
    }
}

// $reading->assessments, and $reading->skippedEntries for the entries that claim nothing.
```

</details>

## 📝 Things to know

- An assessment covers a finding only while it has not expired, the component keeps the version it names, and the
  advisory still answers to one of its identities.
- When several assessments cover one finding, the most alarming decides. A newer assessment does not replace an older
  one, so retire the old one.
- Store the identities from `AdvisoryFingerprint::identitiesOf()`, not only the canonical fingerprint.
- Reasons are free text that someone typed. Escape them before you show them.
- The reader rejects a whole document if any entry is unclear. The finding then stays visible.
- Cap the size of a document before you read it.

Details are in [Matching assessments to findings](docs/matching.md) and [CycloneDX VEX](docs/cyclonedx.md).

## 📙 Documentation

- [Public API reference](docs/api.md): the supported types. Everything else is `@internal`.
- [Matching assessments to findings](docs/matching.md)
- [CycloneDX VEX](docs/cyclonedx.md)

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow.

## 🔒 Security

Report vulnerabilities as described in the [Security Policy](SECURITY.md).

## ⭐ License

This package is licensed under [MIT](LICENSE.md).

## 💬 Support

Issues and feature requests go to the
[GitHub issue tracker](https://github.com/mteu/advisory-assessor/issues).
