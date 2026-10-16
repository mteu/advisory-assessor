<?php

declare(strict_types=1);

/*
 * This file is part of the library "mteu/advisory-assessor".
 *
 * Copyright (c) 2026 Martin Adler <mteu@mailbox.org>
 *
 * For the full copyright and license information, please read the
 * LICENSE.md file that was distributed with this source code.
 */

namespace mteu\AdvisoryAssessor\CycloneDx;

use mteu\AdvisoryAssessor\Assessment\Justification;
use mteu\AdvisoryAssessor\Assessment\Assessment;
use mteu\AdvisoryAssessor\Assessment\Status;
use mteu\AdvisoryAssessor\Document\Author;
use mteu\AdvisoryAssessor\Document\AuthorKind;
use mteu\AdvisoryAssessor\Document\VexDocumentMetadata;
use mteu\AdvisoryMatcher\Source\PackageRef;

/**
 * Writes assessments as a CycloneDX 1.6 VEX document.
 *
 * Output depends only on the input, so a VEX file in a repository diffs
 * cleanly. The SBOMs have no `serialNumber` to point into, so every component
 * is repeated with its purl.
 *
 * Origin and expiry are not written. CycloneDX has no field for them, and an
 * origin names people.
 *
 * @phpstan-type Source array{name: string, url: string}
 * @phpstan-type Reference array{id: string, source: Source}
 * @phpstan-type Analysis array{state: string, justification?: string, response?: list<string>, detail?: string, firstIssued: string, lastUpdated: string}
 * @phpstan-type Property array{name: string, value: string}
 * @phpstan-type Vulnerability array{id: string, source?: Source, references?: list<Reference>, analysis: Analysis, affects: list<array{ref: string}>, properties?: list<Property>}
 * @phpstan-type Component array{type: string, 'bom-ref': string, group?: string, name: string, version: string, purl: string}
 * @phpstan-type Metadata array{timestamp: string, authors?: list<array{name: string}>, manufacturer?: array{name: string}}
 */
final readonly class CycloneDxVexWriter
{
    /**
     * Carries a justification CycloneDX lacks next to the nearest one it has,
     * so reading the document back restores it.
     */
    public const string JUSTIFICATION_PROPERTY = 'mteu:vex:justification';

    /**
     * Carries the severity an `affected` assessment accepted. CycloneDX has no
     * field for it, and without it the assessment cannot be read back.
     */
    public const string ACCEPTED_SEVERITY_PROPERTY = 'mteu:vex:accepted_severity';

    private const string SPEC_VERSION = '1.6';

    private const string TIMESTAMP_FORMAT = 'Y-m-d\TH:i:s\Z';

    private const int JSON_FLAGS = JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;

    public function canWrite(Assessment $assessment): bool
    {
        return $this->selectVulnerabilityIds($assessment) !== [];
    }

    /**
     * @param list<Assessment> $assessments
     * @throws UnexportableAssessments
     * @throws ContradictingAssessments
     * @throws \InvalidArgumentException when the document is issued before an assessment it carries
     */
    public function write(array $assessments, ExportScope $scope, VexDocumentMetadata $document): string
    {
        $included = array_values(array_filter(
            $assessments,
            static fn (Assessment $assessment): bool => $scope->includes($assessment->status),
        ));

        $this->rejectUnexportable($included);
        $this->rejectContradictingAssessments($included);
        $this->rejectIssueTimeBeforeNewestAssessment($document, $included);

        $vulnerabilities = array_map($this->buildVulnerability(...), $included);
        usort(
            $vulnerabilities,
            static fn (array $left, array $right): int => [$left['id'], $left['affects'][0]['ref']] <=> [$right['id'], $right['affects'][0]['ref']],
        );

        return $this->encode([
            'bomFormat' => 'CycloneDX',
            'specVersion' => self::SPEC_VERSION,
            'serialNumber' => 'urn:uuid:' . strtolower($document->documentId),
            'version' => $document->version,
            'metadata' => $this->buildMetadata($document),
            'components' => $this->buildComponents($included),
            'vulnerabilities' => $vulnerabilities,
        ]);
    }

    /**
     * One assessment as the CycloneDX vulnerability object a project can paste
     * into the VEX it keeps in its repository.
     *
     * @throws UnexportableAssessments
     */
    public function writeVulnerability(Assessment $assessment): string
    {
        $this->rejectUnexportable([$assessment]);

        return $this->encode($this->buildVulnerability($assessment));
    }

    /**
     * @param list<Assessment> $assessments
     * @throws UnexportableAssessments
     */
    private function rejectUnexportable(array $assessments): void
    {
        $unexportable = array_values(array_filter(
            $assessments,
            fn (Assessment $assessment): bool => !$this->canWrite($assessment),
        ));

        if ($unexportable !== []) {
            throw new UnexportableAssessments($unexportable);
        }
    }

    /**
     * @param list<Assessment> $assessments
     * @throws ContradictingAssessments
     */
    private function rejectContradictingAssessments(array $assessments): void
    {
        // An identity names no version, so the component is part of the key.
        $positionsByClaim = [];
        foreach ($assessments as $position => $assessment) {
            $component = $assessment->component->toString();
            foreach ($assessment->identities as $identity) {
                $positionsByClaim[$component . "\n" . $identity][$position] = true;
            }
        }

        $contradicting = [];
        foreach ($positionsByClaim as $positions) {
            if (count($positions) > 1) {
                $contradicting += $positions;
            }
        }

        if ($contradicting === []) {
            return;
        }

        ksort($contradicting);

        throw new ContradictingAssessments(array_values(array_intersect_key($assessments, $contradicting)));
    }

    /**
     * CISA's minimum requirements: a document is last updated no earlier than
     * the newest statement it carries.
     *
     * @param list<Assessment> $assessments
     */
    private function rejectIssueTimeBeforeNewestAssessment(VexDocumentMetadata $document, array $assessments): void
    {
        foreach ($assessments as $assessment) {
            if ($assessment->issuedAt > $document->issuedAt) {
                throw new \InvalidArgumentException('A VEX document cannot be issued before an assessment it carries.');
            }
        }
    }

    /**
     * @return Metadata
     */
    private function buildMetadata(VexDocumentMetadata $document): array
    {
        $metadata = ['timestamp' => $this->formatTimestamp($document->issuedAt)];

        return $metadata + $this->describeAuthor($document->author);
    }

    /**
     * @return array{authors: list<array{name: string}>}|array{manufacturer: array{name: string}}
     */
    private function describeAuthor(Author $author): array
    {
        return match ($author->kind) {
            AuthorKind::Person => ['authors' => [['name' => $author->name]]],
            AuthorKind::Organization => ['manufacturer' => ['name' => $author->name]],
        };
    }

    /**
     * @return Vulnerability
     */
    private function buildVulnerability(Assessment $assessment): array
    {
        [$primary, $others] = $this->splitPrimaryId($assessment);

        $vulnerability = ['id' => $primary->id];

        $source = $this->describeSource($primary);
        if ($source !== []) {
            $vulnerability['source'] = $source;
        }

        $references = $this->buildReferences($others);
        if ($references !== []) {
            $vulnerability['references'] = $references;
        }

        $vulnerability['analysis'] = $this->buildAnalysis($assessment);
        $vulnerability['affects'] = [['ref' => $assessment->component->toString()]];

        $properties = $this->buildProperties($assessment);
        if ($properties !== []) {
            $vulnerability['properties'] = $properties;
        }

        return $vulnerability;
    }

    /**
     * @return list<Property>
     */
    private function buildProperties(Assessment $assessment): array
    {
        $properties = [];

        if ($assessment->justification === Justification::ComponentNotPresent) {
            $properties[] = ['name' => self::JUSTIFICATION_PROPERTY, 'value' => Justification::ComponentNotPresent->value];
        }

        if ($assessment->acceptedSeverity !== null) {
            $properties[] = ['name' => self::ACCEPTED_SEVERITY_PROPERTY, 'value' => $assessment->acceptedSeverity->value];
        }

        return $properties;
    }

    /**
     * @return array{VulnerabilityId, list<VulnerabilityId>}
     */
    private function splitPrimaryId(Assessment $assessment): array
    {
        $ids = $this->selectVulnerabilityIds($assessment);
        $primary = array_shift($ids);

        if ($primary === null) {
            throw new \LogicException('Unexportable assessments are rejected before they are built.');
        }

        return [$primary, $ids];
    }

    /**
     * @param list<VulnerabilityId> $ids
     * @return list<Reference>
     */
    private function buildReferences(array $ids): array
    {
        $references = [];
        foreach ($ids as $id) {
            // A reference needs a source, and a feed's own id has none. The
            // CVE or GHSA is enough to match on.
            $source = $this->describeSource($id);
            if ($source !== []) {
                $references[] = ['id' => $id->id, 'source' => $source];
            }
        }

        return $references;
    }

    /**
     * @return Analysis
     */
    private function buildAnalysis(Assessment $assessment): array
    {
        $analysis = ['state' => $this->mapState($assessment->status)];

        if ($assessment->justification !== null) {
            $analysis['justification'] = $this->mapJustification($assessment->justification);
        }

        if ($assessment->response !== null) {
            $analysis['response'] = [$assessment->response->value];
        }

        if (trim($assessment->reason) !== '') {
            $analysis['detail'] = $assessment->reason;
        }

        // Assessments are immutable. A change is a new one; the caller retires
        // the old one.
        $analysis['firstIssued'] = $this->formatTimestamp($assessment->issuedAt);
        $analysis['lastUpdated'] = $analysis['firstIssued'];

        return $analysis;
    }

    /**
     * @param list<Assessment> $assessments
     * @return list<Component>
     */
    private function buildComponents(array $assessments): array
    {
        $components = [];
        foreach ($assessments as $assessment) {
            $components[$assessment->component->toString()] = $this->buildComponent($assessment->component);
        }
        ksort($components, SORT_STRING);

        return array_values($components);
    }

    /**
     * @return Component
     */
    private function buildComponent(PackageRef $component): array
    {
        $purl = $component->toString();

        $built = ['type' => 'library', 'bom-ref' => $purl];
        if ($component->package->namespace !== '') {
            $built['group'] = $component->package->namespace;
        }
        $built['name'] = $component->package->name;
        $built['version'] = $component->version;
        $built['purl'] = $purl;

        return $built;
    }

    /**
     * @return list<VulnerabilityId> readable ids only, most widely understood first, each once
     */
    private function selectVulnerabilityIds(Assessment $assessment): array
    {
        $ids = array_values(array_filter(
            VulnerabilityId::fromIdentities($assessment->identities),
            static fn (VulnerabilityId $id): bool => $id->kind->isReadableByOtherTools(),
        ));

        usort(
            $ids,
            static fn (VulnerabilityId $left, VulnerabilityId $right): int => $left->kind->getPreferenceRank() <=> $right->kind->getPreferenceRank(),
        );

        $unique = [];
        foreach ($ids as $id) {
            $unique[$id->id] ??= $id;
        }

        return array_values($unique);
    }

    /**
     * @return Source|array{} empty when the id does not say which feed it is from
     */
    private function describeSource(VulnerabilityId $id): array
    {
        return match ($id->kind) {
            IdentityKind::Cve => ['name' => 'NVD', 'url' => 'https://nvd.nist.gov/vuln/detail/' . rawurlencode($id->id)],
            IdentityKind::Ghsa => ['name' => 'GitHub', 'url' => 'https://github.com/advisories/' . rawurlencode($id->id)],
            IdentityKind::Native, IdentityKind::Hash => [],
        };
    }

    private function mapState(Status $status): string
    {
        return match ($status) {
            Status::NotAffected => 'not_affected',
            Status::FalsePositive => 'false_positive',
            Status::Affected => 'exploitable',
            // `resolved_with_pedigree` would claim that the component's
            // pedigree carries the fix. Nothing here writes a pedigree.
            Status::Fixed => 'resolved',
            Status::UnderInvestigation => 'in_triage',
        };
    }

    private function mapJustification(Justification $justification): string
    {
        return match ($justification) {
            Justification::CodeNotPresent,
            Justification::CodeNotReachable,
            Justification::RequiresConfiguration,
            Justification::RequiresDependency,
            Justification::RequiresEnvironment,
            Justification::ProtectedByCompiler,
            Justification::ProtectedAtRuntime,
            Justification::ProtectedAtPerimeter,
            Justification::ProtectedByMitigatingControl => $justification->value,
            Justification::ComponentNotPresent => Justification::CodeNotPresent->value,
        };
    }

    private function formatTimestamp(\DateTimeImmutable $time): string
    {
        return $time->setTimezone(new \DateTimeZone('UTC'))->format(self::TIMESTAMP_FORMAT);
    }

    /**
     * @param array<string, mixed> $document mixed because it is a JSON tree of the shapes declared on this class
     */
    private function encode(array $document): string
    {
        return json_encode($document, self::JSON_FLAGS) . "\n";
    }
}
