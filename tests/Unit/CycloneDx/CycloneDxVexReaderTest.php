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

namespace mteu\AdvisoryAssessor\Tests\Unit\CycloneDx;

use mteu\AdvisoryMatcher\Source\PackageRef;
use mteu\AdvisoryAssessor\CycloneDx\CycloneDxVexReader;
use mteu\AdvisoryAssessor\CycloneDx\RejectedVexEntries;
use mteu\AdvisoryAssessor\CycloneDx\RejectedVexEntry;
use mteu\AdvisoryAssessor\CycloneDx\RejectionReason;
use mteu\AdvisoryAssessor\CycloneDx\UnreadableVexDocument;
use mteu\AdvisoryAssessor\CycloneDx\VexReading;
use mteu\AdvisoryAssessor\Assessment\Justification;
use mteu\AdvisoryAssessor\Assessment\Origin;
use mteu\AdvisoryAssessor\Assessment\Response;
use mteu\AdvisoryAssessor\Assessment\Assessment;
use mteu\AdvisoryAssessor\Assessment\Status;
use mteu\AdvisoryAssessor\Tests\Unit\Clock\FrozenClock;
use mteu\AdvisoryMatcher\Advisory\Severity;
use mteu\SbomParser\Exception\SbomParseException;
use mteu\SbomParser\Parser\CycloneDxParser;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;

#[CoversClass(CycloneDxVexReader::class)]
#[CoversClass(VexReading::class)]
#[CoversClass(RejectedVexEntries::class)]
#[CoversClass(RejectedVexEntry::class)]
#[CoversClass(UnreadableVexDocument::class)]
final class CycloneDxVexReaderTest extends TestCase
{
    private const string NOW = '2026-10-08T12:30:00+00:00';

    private const string KERNEL = 'pkg:composer/symfony/http-kernel@5.4.19';

    private const string PSR7 = 'pkg:composer/guzzlehttp/psr7@2.4.1';

    /**
     * @return iterable<string, array{RejectionReason, list<array{int, string}>}>
     */
    public static function rejectionsAndTheEntriesTheyName(): iterable
    {
        foreach (RejectionReason::cases() as $reason) {
            $named = match ($reason) {
                RejectionReason::ComponentInAnotherDocument => [[0, 'urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#' . self::KERNEL]],
                RejectionReason::UnknownComponent => [[0, self::PSR7]],
                RejectionReason::AmbiguousComponent,
                RejectionReason::VersionRange,
                RejectionReason::ComponentWithoutPackageUrl,
                RejectionReason::InvalidPackageUrl => [[0, self::KERNEL]],
                RejectionReason::UnsupportedEcosystem => [[0, 'pkg:pypi/django@4.2.0']],
                RejectionReason::Duplicate => [[0, self::KERNEL], [1, self::KERNEL]],
                RejectionReason::MissingVulnerabilityId,
                RejectionReason::MissingJustification,
                RejectionReason::UnknownJustification,
                RejectionReason::MissingResponse,
                RejectionReason::MissingAcceptedSeverity,
                RejectionReason::UnknownAcceptedSeverity,
                RejectionReason::MissingReason,
                RejectionReason::MissingIssueTime,
                RejectionReason::IssuedInTheFuture,
                RejectionReason::NoAffectedComponent => [[0, '']],
            };

            yield $reason->value => [$reason, $named];
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unreadableDocuments(): iterable
    {
        yield 'not JSON' => ['{"bomFormat": "CycloneDX",'];
        yield 'not CycloneDX' => [self::fixture('Unreadable/not-cyclonedx.json')];
        yield 'CycloneDX before 1.4' => [self::fixture('Unreadable/cyclonedx-1.3.json')];
        yield 'a value CycloneDX does not define' => [self::fixture('Unreadable/unknown-justification-value.json')];
    }

    /**
     * @return iterable<string, array{list<array{string, string}>, list<string>}>
     */
    public static function claimsAboutOneAdvisoryOnOneComponent(): iterable
    {
        yield 'three times' => [
            [[self::KERNEL, 'CVE-2026-1234'], [self::KERNEL, 'CVE-2026-1234'], [self::KERNEL, 'CVE-2026-1234']],
            [self::KERNEL, self::KERNEL, self::KERNEL],
        ];

        yield 'one package spelled two ways' => [
            [['pkg:npm/@acme/widgets@2.1.0', 'CVE-2026-1234'], ['pkg:npm/%40acme/widgets@2.1.0', 'CVE-2026-1234']],
            ['pkg:npm/@acme/widgets@2.1.0', 'pkg:npm/%40acme/widgets@2.1.0'],
        ];
    }

    /**
     * @return iterable<string, array{list<array{string, string}>}>
     */
    public static function claimsThatAreNoDuplicates(): iterable
    {
        yield 'two advisories on one component' => [[[self::KERNEL, 'CVE-2026-1234'], [self::KERNEL, 'CVE-2026-5678']]];
        yield 'one advisory on two versions' => [[[self::KERNEL, 'CVE-2026-1234'], ['pkg:composer/symfony/http-kernel@5.4.20', 'CVE-2026-1234']]];
    }

    /**
     * @return iterable<string, array{\DateInterval}>
     */
    public static function nonPositiveLifetimes(): iterable
    {
        yield 'zero' => [new \DateInterval('PT0S')];

        $negative = new \DateInterval('P1D');
        $negative->invert = 1;
        yield 'negative' => [$negative];
    }

    #[Test]
    public function readsACycloneDx14DocumentWhoseEntriesCarryNoIssueTime(): void
    {
        $assessments = $this->read(self::fixture('cyclonedx-1.4.json'))->assessments;

        self::assertCount(2, $assessments);
        [$affected, $notAffected] = $assessments;

        self::assertSame(Status::Affected, $affected->status);
        self::assertSame(['composer|symfony/http-kernel|cve|CVE-2026-1234'], $affected->identities);
        self::assertSame(self::KERNEL, $affected->component->toString());
        self::assertSame('Upgrading with the next release.', $affected->reason);
        self::assertEquals(new \DateTimeImmutable('2026-09-15T08:00:00Z'), $affected->issuedAt);

        self::assertSame(Status::NotAffected, $notAffected->status);
        self::assertSame(Justification::RequiresConfiguration, $notAffected->justification);
        self::assertSame(['npm|@acme/widgets|ghsa|GHSA-ABCD-EFGH-IJKL'], $notAffected->identities);
        self::assertSame('pkg:npm/%40acme/widgets@2.1.0', $notAffected->component->toString());
    }

    #[Test]
    public function keepsTheFirstResponseListedBecauseAAssessmentHoldsOne(): void
    {
        $affected = $this->read(self::fixture('cyclonedx-1.4.json'))->assessments[0];

        self::assertSame(Response::Update, $affected->response);
    }

    #[Test]
    public function acceptsTheHighestRatingWhenTheAcceptedSeverityIsNotWritten(): void
    {
        $affected = $this->read(self::fixture('cyclonedx-1.4.json'))->assessments[0];

        self::assertSame(Severity::High, $affected->acceptedSeverity);
    }

    #[Test]
    public function prefersTheWrittenAcceptedSeverityOverTheRatings(): void
    {
        $affected = $this->readLatestFixture()[6];

        self::assertSame(Severity::Critical, $affected->acceptedSeverity);
        self::assertSame(Response::Rollback, $affected->response);
    }

    #[Test]
    public function readsACycloneDx16DocumentAndSkipsTheEntriesThatClaimNothing(): void
    {
        $reading = $this->read(self::fixture('cyclonedx-1.6.json'));

        self::assertSame([0, 1], $reading->skippedEntries);
        self::assertSame(
            [
                Status::NotAffected,
                Status::NotAffected,
                Status::FalsePositive,
                Status::Fixed,
                Status::Fixed,
                Status::UnderInvestigation,
                Status::Affected,
            ],
            array_map(static fn (Assessment $assessment): Status => $assessment->status, $reading->assessments),
        );
    }

    #[Test]
    public function readsOneAssessmentPerAffectedComponentIncludingNestedOnes(): void
    {
        [$onKernel, $onPsr7] = $this->readLatestFixture();

        self::assertSame(self::KERNEL, $onKernel->component->toString());
        self::assertSame(self::PSR7, $onPsr7->component->toString());
        self::assertSame(
            ['composer|guzzlehttp/psr7|cve|CVE-2026-0003', 'composer|guzzlehttp/psr7|ghsa|GHSA-WXYZ-0003-MNOP'],
            $onPsr7->identities,
        );
    }

    #[Test]
    public function readsTheIdAndEveryReferenceAsTheMatcherSpellsThem(): void
    {
        $assessments = $this->readLatestFixture();

        self::assertSame(
            ['composer|symfony/http-kernel|cve|CVE-2026-0003', 'composer|symfony/http-kernel|ghsa|GHSA-WXYZ-0003-MNOP'],
            $assessments[0]->identities,
        );
        self::assertSame(['composer|symfony/http-kernel|id|PKSA-0004-0004-0004'], $assessments[2]->identities);
    }

    #[Test]
    #[TestWith(['pkg:composer/symfony/http-kernel'])]
    #[TestWith(['pkg:composer/symfony/http-kernel@%20'])]
    public function rejectsAComponentWhosePackageUrlNamesNoVersion(string $purl): void
    {
        $rejected = $this->readRejected(self::documentClaiming([[$purl, 'CVE-2026-0003']]));

        self::assertCount(1, $rejected);
        self::assertSame(RejectionReason::InvalidPackageUrl, $rejected[0]->reason);
    }

    #[Test]
    public function rejectsTheRuntimeUnderAPackageUrlTypeTheSpecificationDoesNotRegister(): void
    {
        $rejected = $this->readRejected(self::documentClaiming([['pkg:php/php@8.3.6', 'CVE-2026-0003']]));

        self::assertSame(RejectionReason::UnsupportedEcosystem, $rejected[0]->reason);
    }

    #[Test]
    public function spellsAMixedCaseComposerPackageAsTheFeedsDo(): void
    {
        $assessments = $this->read(self::documentClaiming([['pkg:composer/Symfony/HTTP-Kernel@5.4.19', 'CVE-2026-0003']]))->assessments;

        self::assertSame(['composer|symfony/http-kernel|cve|CVE-2026-0003'], $assessments[0]->identities);
        self::assertSame(self::KERNEL, $assessments[0]->component->toString());
    }

    #[Test]
    public function prefersTheJustificationPropertyOverTheNearestCycloneDxJustification(): void
    {
        self::assertSame(Justification::ComponentNotPresent, $this->readLatestFixture()[0]->justification);
    }

    #[Test]
    public function ignoresAJustificationAndAResponseTheStatusDoesNotTakeAndAPedigree(): void
    {
        $assessments = $this->readLatestFixture();

        self::assertNull($assessments[2]->justification);
        self::assertNull($assessments[2]->response);
        self::assertSame('Patched in our fork.', $assessments[3]->reason);
    }

    #[Test]
    public function readsAnEntryUnderInvestigationWithoutAReason(): void
    {
        self::assertSame('', $this->readLatestFixture()[5]->reason);
    }

    #[Test]
    public function prefersFirstIssuedOverTheDocumentTimestamp(): void
    {
        self::assertEquals(new \DateTimeImmutable('2026-10-02T10:15:00Z'), $this->readLatestFixture()[0]->issuedAt);
    }

    #[Test]
    public function takesTheOriginFromTheCaller(): void
    {
        $origin = Origin::pipeline('acme/shop', 'a1b2c3d4');

        $assessment = $this->reader()->read(self::fixture('minimal.json'), $origin, null)->assessments[0];

        self::assertSame($origin, $assessment->origin);
    }

    #[Test]
    public function letsAAssessmentExpireOneLifetimeAfterItWasIssued(): void
    {
        $assessment = $this->reader()->read(self::fixture('minimal.json'), self::origin(), new \DateInterval('P90D'))->assessments[0];

        self::assertEquals(new \DateTimeImmutable('2026-12-30T00:00:00Z'), $assessment->expiresAt);
    }

    #[Test]
    public function letsAAssessmentNeverExpireWithoutALifetime(): void
    {
        self::assertNull($this->read(self::fixture('minimal.json'))->assessments[0]->expiresAt);
    }

    #[Test]
    #[DataProvider('nonPositiveLifetimes')]
    public function refusesALifetimeThatIsNotPositive(\DateInterval $lifetime): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->reader()->read(self::fixture('minimal.json'), self::origin(), $lifetime);
    }

    /**
     * @param list<array{int, string}> $expected each rejected entry's index and ref
     */
    #[Test]
    #[DataProvider('rejectionsAndTheEntriesTheyName')]
    public function rejectsTheDocumentAndNamesTheEntry(RejectionReason $reason, array $expected): void
    {
        $entries = $this->readRejected(self::fixture('Rejected/' . $reason->value . '.json'));

        self::assertSame(
            array_map(static fn (array $named): array => [...$named, $reason], $expected),
            array_map(static fn (RejectedVexEntry $entry): array => [$entry->index, $entry->ref, $entry->reason], $entries),
        );
    }

    #[Test]
    public function namesTheVulnerabilityIdOfARejectedEntryAsWritten(): void
    {
        $entries = $this->readRejected(self::fixture('Rejected/duplicate.json'));

        self::assertSame(['CVE-2026-1234', 'GHSA-jfh8-c2jp-5v3q'], array_map(
            static fn (RejectedVexEntry $entry): string => $entry->vulnerabilityId,
            $entries,
        ));
    }

    /**
     * @param list<array{string, string}> $claims
     * @param list<string> $expectedRefs
     */
    #[Test]
    #[DataProvider('claimsAboutOneAdvisoryOnOneComponent')]
    public function rejectsEveryEntryThatClaimsTheSameAdvisoryOnTheSameComponent(array $claims, array $expectedRefs): void
    {
        $entries = $this->readRejected(self::documentClaiming($claims));

        self::assertSame(
            array_map(static fn (int $index, string $ref): array => [$index, $ref, RejectionReason::Duplicate], array_keys($expectedRefs), $expectedRefs),
            array_map(static fn (RejectedVexEntry $entry): array => [$entry->index, $entry->ref, $entry->reason], $entries),
        );
    }

    /**
     * @param list<array{string, string}> $claims
     */
    #[Test]
    #[DataProvider('claimsThatAreNoDuplicates')]
    public function readsClaimsThatDifferInAdvisoryOrVersion(array $claims): void
    {
        self::assertCount(count($claims), $this->read(self::documentClaiming($claims))->assessments);
    }

    #[Test]
    #[Group('performance')]
    public function readsThousandsOfEntriesInLinearTime(): void
    {
        $claims = [];
        for ($i = 0; $i < 3000; $i++) {
            $claims[] = [sprintf('pkg:composer/acme/package-%d@1.0.0', $i), sprintf('CVE-2026-%05d', $i)];
        }
        $json = self::documentClaiming($claims);

        $startedAt = hrtime(true);
        $assessments = $this->read($json)->assessments;
        $seconds = (hrtime(true) - $startedAt) / 1e9;

        self::assertCount(3000, $assessments);
        // Comparing every pair took about 24 s here, one pass about 1.5 s.
        self::assertLessThan(10.0, $seconds);
    }

    #[Test]
    public function rejectsTheWholeDocumentNamingEveryProblemAtOnce(): void
    {
        $entries = $this->readRejected(self::fixture('several-rejected.json'));

        self::assertEquals(
            [
                new RejectedVexEntry(1, 'GHSA-jfh8-c2jp-5v3q', '', RejectionReason::MissingReason),
                new RejectedVexEntry(1, 'GHSA-jfh8-c2jp-5v3q', self::PSR7, RejectionReason::UnknownComponent),
                new RejectedVexEntry(3, 'CVE-2026-9999', '', RejectionReason::NoAffectedComponent),
            ],
            $entries,
        );
    }

    #[Test]
    public function namesOnlyTheIndicesInTheMessageBecauseTheRestComesFromTheDocument(): void
    {
        try {
            $this->read(self::fixture('several-rejected.json'));
            self::fail('The document should have been rejected.');
        } catch (RejectedVexEntries $exception) {
            self::assertSame('The VEX document holds entries that cannot be read, at index 1, 3.', $exception->getMessage());
        }
    }

    #[Test]
    #[DataProvider('unreadableDocuments')]
    public function refusesADocumentItCannotReadBeforeLookingAtAnyEntry(string $json): void
    {
        try {
            $this->read($json);
            self::fail('The document should have been refused.');
        } catch (UnreadableVexDocument $exception) {
            self::assertSame('Not a CycloneDX 1.4 to 1.7 JSON document.', $exception->getMessage());
            self::assertInstanceOf(SbomParseException::class, $exception->getPrevious());
        }
    }

    #[Test]
    public function refusesANegativeEntryIndex(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new RejectedVexEntry(-1, 'CVE-2026-1234', '', RejectionReason::Duplicate);
    }

    private function reader(): CycloneDxVexReader
    {
        return new CycloneDxVexReader(new CycloneDxParser(), FrozenClock::at(self::NOW));
    }

    /**
     * @throws RejectedVexEntries
     * @throws UnreadableVexDocument
     */
    private function read(string $json): VexReading
    {
        return $this->reader()->read($json, self::origin(), null);
    }

    /**
     * @return list<Assessment>
     */
    private function readLatestFixture(): array
    {
        return $this->read(self::fixture('cyclonedx-1.6.json'))->assessments;
    }

    /**
     * @return list<RejectedVexEntry>
     */
    private function readRejected(string $json): array
    {
        try {
            $this->read($json);
        } catch (RejectedVexEntries $exception) {
            return $exception->entries;
        }

        self::fail('The document should have been rejected.');
    }

    private static function origin(): Origin
    {
        return Origin::pipeline('acme/shop', 'a1b2c3d4');
    }

    /**
     * Each claim is a not_affected entry; each purl is also the component's `bom-ref`.
     *
     * @param list<array{string, string}> $claims purl and vulnerability id
     */
    private static function documentClaiming(array $claims): string
    {
        $components = [];
        $vulnerabilities = [];
        foreach ($claims as [$purl, $vulnerabilityId]) {
            $components[$purl] = ['type' => 'library', 'bom-ref' => $purl, 'name' => 'package', 'purl' => $purl];
            $vulnerabilities[] = [
                'id' => $vulnerabilityId,
                'analysis' => [
                    'state' => 'not_affected',
                    'justification' => 'code_not_reachable',
                    'detail' => 'Never called.',
                    'firstIssued' => '2026-10-01T00:00:00Z',
                ],
                'affects' => [['ref' => $purl]],
            ];
        }

        return json_encode([
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.6',
            'version' => 1,
            'components' => array_values($components),
            'vulnerabilities' => $vulnerabilities,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    private static function fixture(string $name): string
    {
        return (string)file_get_contents(dirname(__DIR__, 2) . '/Fixtures/CycloneDx/Vex/' . $name);
    }
}
