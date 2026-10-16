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
use mteu\AdvisoryAssessor\Assessment\Origin;
use mteu\AdvisoryAssessor\Assessment\Response;
use mteu\AdvisoryAssessor\Assessment\Assessment;
use mteu\AdvisoryAssessor\Assessment\Status;
use mteu\AdvisoryMatcher\Advisory\AdvisoryFingerprint;
use mteu\AdvisoryMatcher\Advisory\Severity;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Source\PackageRef;
use mteu\SbomParser\Entity\Bom;
use mteu\SbomParser\Entity\Component;
use mteu\SbomParser\Entity\Vulnerability\ImpactAnalysisState;
use mteu\SbomParser\Entity\Vulnerability\Vulnerability;
use mteu\SbomParser\Entity\Vulnerability\VulnerabilityAffects;
use mteu\SbomParser\Entity\Vulnerability\VulnerabilityAnalysis;
use mteu\SbomParser\Exception\SbomParseException;
use mteu\SbomParser\Parser\CycloneDxParser;
use Psr\Clock\ClockInterface;

/**
 * Reads assessments from a CycloneDX 1.4 to 1.7 VEX document.
 *
 * An assessment hides a finding, so anything unclear is rejected. The whole
 * document goes, with every bad entry named: importing only the good ones would
 * drop assessments the author meant to keep.
 *
 * Components come from the purl behind the entry's `bom-ref`, never from the
 * `bom-ref` itself.
 *
 * @phpstan-type ReadAssessment array{index: int, vulnerabilityId: string, ref: string, assessment: Assessment}
 * @phpstan-type Claim array{vulnerabilityIds: non-empty-list<string>, status: Status, reason: string, origin: Origin, issuedAt: \DateTimeImmutable, justification: Justification|null, response: Response|null, acceptedSeverity: Severity|null, expiresAt: \DateTimeImmutable|null}
 */
final readonly class CycloneDxVexReader
{
    /**
     * A BOM-Link points into another document, which the reader does not have.
     */
    private const string BOM_LINK_PREFIX = 'urn:cdx:';

    public function __construct(
        private CycloneDxParser $parser,
        private ClockInterface $clock,
    ) {
    }

    /**
     * @param Origin $origin who brought the document; CycloneDX does not say
     * @param \DateInterval|null $lifetime how long an assessment holds after it was issued; null for never
     * @throws UnreadableVexDocument
     * @throws RejectedVexEntries
     * @throws \InvalidArgumentException when the lifetime is not positive
     */
    public function read(string $json, Origin $origin, ?\DateInterval $lifetime): VexReading
    {
        $now = $this->clock->now();
        if ($lifetime !== null && $now->add($lifetime) <= $now) {
            throw new \InvalidArgumentException('An assessment lifetime has to be positive.');
        }

        $bom = $this->parse($json);
        $componentsByRef = $this->indexComponentsByRef($bom);

        $readPerEntry = [];
        $rejectedPerEntry = [];
        $skipped = [];
        foreach (array_values($bom->vulnerabilities ?? []) as $index => $vulnerability) {
            $analysis = $vulnerability->analysis;
            if ($analysis === null || $analysis->state === null) {
                $skipped[] = $index;
                continue;
            }

            $claim = null;
            try {
                $claim = $this->readClaim($index, $vulnerability, $analysis, $analysis->state, $bom, $origin, $lifetime, $now);
            } catch (RejectedVexEntries $rejection) {
                $rejectedPerEntry[] = $rejection->entries;
            }

            // Read the components even when the claim was rejected, so every
            // problem with the entry is named at once.
            try {
                $readPerEntry[] = $this->readEntry($index, $vulnerability, $claim, $componentsByRef);
            } catch (RejectedVexEntries $rejection) {
                $rejectedPerEntry[] = $rejection->entries;
            }
        }

        $read = array_merge(...$readPerEntry);
        $rejected = array_merge($this->rejectDuplicates($read), ...$rejectedPerEntry);
        if ($rejected !== []) {
            usort(
                $rejected,
                static fn (RejectedVexEntry $left, RejectedVexEntry $right): int => [$left->index, $left->ref] <=> [$right->index, $right->ref],
            );

            throw new RejectedVexEntries($rejected);
        }

        return new VexReading(
            array_map(static fn (array $entry): Assessment => $entry['assessment'], $read),
            $skipped,
        );
    }

    /**
     * @throws UnreadableVexDocument
     */
    private function parse(string $json): Bom
    {
        try {
            return $this->parser->parseFromJson($json);
        } catch (SbomParseException $exception) {
            throw UnreadableVexDocument::becauseParsingFailed($exception);
        }
    }

    /**
     * @return array<array-key, list<Component>> a list, so a `bom-ref` used twice shows up as ambiguous
     */
    private function indexComponentsByRef(Bom $bom): array
    {
        $index = [];
        foreach ($bom->getAllComponents() as $component) {
            if ($component->bomRef !== null) {
                $index[$component->bomRef][] = $component;
            }
        }

        return $index;
    }

    /**
     * @return Claim
     * @throws RejectedVexEntries naming every reason the claim cannot be read
     */
    private function readClaim(
        int $index,
        Vulnerability $vulnerability,
        VulnerabilityAnalysis $analysis,
        ImpactAnalysisState $state,
        Bom $bom,
        Origin $origin,
        ?\DateInterval $lifetime,
        \DateTimeImmutable $now,
    ): array {
        $status = $this->mapState($state);
        $rejections = [];

        $vulnerabilityIds = $this->readVulnerabilityIds($vulnerability);
        if ($vulnerabilityIds === []) {
            $rejections[] = RejectionReason::MissingVulnerabilityId;
        }

        $justification = null;
        if ($status === Status::NotAffected) {
            $justification = $this->readJustification($vulnerability, $analysis);
            if ($justification instanceof RejectionReason) {
                $rejections[] = $justification;
                $justification = null;
            }
        }

        $response = null;
        $acceptedSeverity = null;
        if ($status === Status::Affected) {
            $response = $this->readResponse($analysis);
            if ($response instanceof RejectionReason) {
                $rejections[] = $response;
                $response = null;
            }

            $acceptedSeverity = $this->readAcceptedSeverity($vulnerability);
            if ($acceptedSeverity instanceof RejectionReason) {
                $rejections[] = $acceptedSeverity;
                $acceptedSeverity = null;
            }
        }

        // The reason is what an outside reader of the assessment gets.
        $reason = $analysis->detail ?? '';
        if ($status !== Status::UnderInvestigation && trim($reason) === '') {
            $rejections[] = RejectionReason::MissingReason;
        }

        $issuedAt = $this->readIssueTime($analysis, $bom, $now);
        if ($issuedAt instanceof RejectionReason) {
            $rejections[] = $issuedAt;
        }

        // The last two are redundant, but they narrow the types for PHPStan.
        if ($rejections !== [] || $vulnerabilityIds === [] || $issuedAt instanceof RejectionReason) {
            throw new RejectedVexEntries(array_map(
                static fn (RejectionReason $reason): RejectedVexEntry => new RejectedVexEntry($index, $vulnerability->id ?? '', '', $reason),
                $rejections,
            ));
        }

        return [
            'vulnerabilityIds' => $vulnerabilityIds,
            'status' => $status,
            'reason' => $reason,
            'origin' => $origin,
            'issuedAt' => $issuedAt,
            'justification' => $justification,
            'response' => $response,
            'acceptedSeverity' => $acceptedSeverity,
            'expiresAt' => $lifetime === null ? null : $issuedAt->add($lifetime),
        ];
    }

    /**
     * @param Claim|null $claim null when the claim was rejected; the components are still read, to name their problems too
     * @param array<array-key, list<Component>> $componentsByRef
     * @return list<ReadAssessment>
     * @throws RejectedVexEntries
     */
    private function readEntry(int $index, Vulnerability $vulnerability, ?array $claim, array $componentsByRef): array
    {
        $vulnerabilityId = $vulnerability->id ?? '';

        $rejected = [];
        $affects = array_values($vulnerability->affects ?? []);
        if ($affects === []) {
            $rejected[] = new RejectedVexEntry($index, $vulnerabilityId, '', RejectionReason::NoAffectedComponent);
        }

        $read = [];
        foreach ($affects as $affected) {
            $component = $this->readComponent($affected, $componentsByRef);

            if ($component instanceof RejectionReason) {
                $rejected[] = new RejectedVexEntry($index, $vulnerabilityId, $affected->ref, $component);
            } elseif ($claim !== null) {
                $read[] = ['index' => $index, 'vulnerabilityId' => $vulnerabilityId, 'ref' => $affected->ref, 'assessment' => $this->buildAssessment($claim, $component)];
            }
        }

        if ($rejected !== []) {
            throw new RejectedVexEntries($rejected);
        }

        return $read;
    }

    /**
     * @param Claim $claim
     */
    private function buildAssessment(array $claim, PackageRef $component): Assessment
    {
        return new Assessment(
            identities: AdvisoryFingerprint::identitiesNaming($component->package, $claim['vulnerabilityIds']),
            component: $component,
            status: $claim['status'],
            reason: $claim['reason'],
            origin: $claim['origin'],
            issuedAt: $claim['issuedAt'],
            justification: $claim['justification'],
            response: $claim['response'],
            acceptedSeverity: $claim['acceptedSeverity'],
            expiresAt: $claim['expiresAt'],
        );
    }

    private function mapState(ImpactAnalysisState $state): Status
    {
        return match ($state) {
            ImpactAnalysisState::NOT_AFFECTED => Status::NotAffected,
            ImpactAnalysisState::FALSE_POSITIVE => Status::FalsePositive,
            ImpactAnalysisState::EXPLOITABLE => Status::Affected,
            // An assessment records no pedigree. Hiding works the same either way.
            ImpactAnalysisState::RESOLVED, ImpactAnalysisState::RESOLVED_WITH_PEDIGREE => Status::Fixed,
            ImpactAnalysisState::IN_TRIAGE => Status::UnderInvestigation,
        };
    }

    /**
     * The id and every reference, as written. `AdvisoryFingerprint::identitiesNaming()`
     * turns them into identities once the component is known.
     *
     * @return list<string>
     */
    private function readVulnerabilityIds(Vulnerability $vulnerability): array
    {
        $candidates = [$vulnerability->id ?? ''];
        foreach ($vulnerability->references ?? [] as $reference) {
            $candidates[] = $reference->id;
        }

        $ids = [];
        foreach ($candidates as $candidate) {
            $id = trim($candidate);

            // A separator would make the identity name something else.
            if ($id !== '' && !str_contains($id, '|')) {
                $ids[] = $id;
            }
        }

        return array_values(array_unique($ids));
    }

    /**
     * The property comes first: it carries `component_not_present`, which
     * CycloneDX lacks, next to the nearest justification CycloneDX has.
     */
    private function readJustification(Vulnerability $vulnerability, VulnerabilityAnalysis $analysis): Justification|RejectionReason
    {
        $property = $this->findPropertyValues($vulnerability, CycloneDxVexWriter::JUSTIFICATION_PROPERTY);
        if ($property !== []) {
            return Justification::tryFrom($property[0]) ?? RejectionReason::UnknownJustification;
        }

        if ($analysis->justification === null) {
            return RejectionReason::MissingJustification;
        }

        return Justification::tryFrom($analysis->justification->value) ?? RejectionReason::UnknownJustification;
    }

    /**
     * An assessment holds one response. The response never decides whether a
     * finding is hidden, so the first one listed stands for all.
     */
    private function readResponse(VulnerabilityAnalysis $analysis): Response|RejectionReason
    {
        $first = ($analysis->response ?? [])[0] ?? null;
        if ($first === null) {
            return RejectionReason::MissingResponse;
        }

        return Response::tryFrom($first->value) ?? RejectionReason::MissingResponse;
    }

    /**
     * Falls back to the highest rating when the property is missing. If the
     * feed rates the advisory higher, the assessment stops covering it.
     */
    private function readAcceptedSeverity(Vulnerability $vulnerability): Severity|RejectionReason
    {
        $property = $this->findPropertyValues($vulnerability, CycloneDxVexWriter::ACCEPTED_SEVERITY_PROPERTY);
        if ($property !== []) {
            return $this->mapAcceptableSeverity($property[0], RejectionReason::UnknownAcceptedSeverity);
        }

        $rating = $vulnerability->getHighestSeverityRating()->severity ?? '';

        return $this->mapAcceptableSeverity(strtolower($rating), RejectionReason::MissingAcceptedSeverity);
    }

    /**
     * `info`, `none` and `unknown` are no severity to accept a risk at.
     */
    private function mapAcceptableSeverity(string $severity, RejectionReason $otherwise): Severity|RejectionReason
    {
        return match ($severity) {
            Severity::Low->value => Severity::Low,
            Severity::Medium->value => Severity::Medium,
            Severity::High->value => Severity::High,
            Severity::Critical->value => Severity::Critical,
            default => $otherwise,
        };
    }

    /**
     * CycloneDX 1.4 has no `firstIssued`, so the document timestamp is the
     * fallback. A future time is rejected: it would push the expiry out, and
     * expiry is there to force a re-review.
     */
    private function readIssueTime(VulnerabilityAnalysis $analysis, Bom $bom, \DateTimeImmutable $now): \DateTimeImmutable|RejectionReason
    {
        $issuedAt = $analysis->firstIssued ?? $bom->metadata?->timestamp;

        if ($issuedAt === null) {
            return RejectionReason::MissingIssueTime;
        }

        if ($issuedAt > $now) {
            return RejectionReason::IssuedInTheFuture;
        }

        return $issuedAt;
    }

    /**
     * @param array<array-key, list<Component>> $componentsByRef
     */
    private function readComponent(VulnerabilityAffects $affected, array $componentsByRef): PackageRef|RejectionReason
    {
        if (str_starts_with($affected->ref, self::BOM_LINK_PREFIX)) {
            return RejectionReason::ComponentInAnotherDocument;
        }

        $components = $componentsByRef[$affected->ref] ?? [];
        if ($components === []) {
            return RejectionReason::UnknownComponent;
        }

        if (count($components) > 1) {
            return RejectionReason::AmbiguousComponent;
        }

        // An assessment names one exact version, the one in the purl.
        if (($affected->versions ?? []) !== []) {
            return RejectionReason::VersionRange;
        }

        $purl = $components[0]->purl ?? '';
        if (trim($purl) === '') {
            return RejectionReason::ComponentWithoutPackageUrl;
        }

        try {
            $component = PackageRef::fromString($purl);
        } catch (\InvalidArgumentException) {
            return RejectionReason::InvalidPackageUrl;
        }

        if (trim($component->version) === '') {
            return RejectionReason::InvalidPackageUrl;
        }

        // No advisory could ever match it.
        if ($component->ecosystem === Ecosystem::Unknown) {
            return RejectionReason::UnsupportedEcosystem;
        }

        return $component;
    }

    /**
     * Two analyses of one advisory on one component leave nothing to tell
     * which one counts, so both go.
     *
     * @param list<ReadAssessment> $read
     * @return list<RejectedVexEntry>
     */
    private function rejectDuplicates(array $read): array
    {
        // An identity names no version, so the component is part of the key.
        $positionsByClaim = [];
        foreach ($read as $position => $entry) {
            $component = $entry['assessment']->component->toString();
            foreach ($entry['assessment']->identities as $identity) {
                $positionsByClaim[$component . "\n" . $identity][$position] = true;
            }
        }

        $duplicates = [];
        foreach ($positionsByClaim as $positions) {
            if (count($positions) < 2) {
                continue;
            }

            foreach (array_keys($positions) as $position) {
                $duplicate = $read[$position];
                $key = $duplicate['index'] . '|' . $duplicate['ref'];
                $duplicates[$key] = new RejectedVexEntry($duplicate['index'], $duplicate['vulnerabilityId'], $duplicate['ref'], RejectionReason::Duplicate);
            }
        }

        return array_values($duplicates);
    }

    /**
     * @return list<string> in the order the document lists them
     */
    private function findPropertyValues(Vulnerability $vulnerability, string $name): array
    {
        $values = [];
        foreach ($vulnerability->properties ?? [] as $property) {
            if ($property->name === $name) {
                $values[] = $property->value;
            }
        }

        return $values;
    }
}
