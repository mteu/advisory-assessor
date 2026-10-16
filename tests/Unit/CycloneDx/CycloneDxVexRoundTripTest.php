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
use mteu\AdvisoryAssessor\CycloneDx\CycloneDxVexWriter;
use mteu\AdvisoryAssessor\CycloneDx\ExportScope;
use mteu\AdvisoryAssessor\Matching\Finding;
use mteu\AdvisoryAssessor\Matching\AssessmentMatcher;
use mteu\AdvisoryAssessor\Assessment\Justification;
use mteu\AdvisoryAssessor\Assessment\Origin;
use mteu\AdvisoryAssessor\Assessment\Response;
use mteu\AdvisoryAssessor\Assessment\Assessment;
use mteu\AdvisoryAssessor\Assessment\Status;
use mteu\AdvisoryAssessor\Tests\Unit\Advisory\AdvisoryBuilder;
use mteu\AdvisoryAssessor\Tests\Unit\Clock\FrozenClock;
use mteu\AdvisoryAssessor\Tests\Unit\Assessment\AssessmentBuilder;
use mteu\AdvisoryAssessor\Tests\Unit\Document\VexDocumentMetadataBuilder;
use mteu\AdvisoryMatcher\Advisory\Advisory;
use mteu\AdvisoryMatcher\Advisory\AdvisoryFingerprint;
use mteu\AdvisoryMatcher\Advisory\Severity;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\SbomParser\Parser\CycloneDxParser;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(CycloneDxVexReader::class)]
#[CoversClass(CycloneDxVexWriter::class)]
final class CycloneDxVexRoundTripTest extends TestCase
{
    private const string NOW = '2026-10-08T12:30:00+00:00';

    private const string KERNEL = 'pkg:composer/symfony/http-kernel@5.4.19';

    private const string WIDGETS = 'pkg:npm/%40acme/widgets@2.1.0';

    #[Test]
    public function readsBackEveryStatusTheWriterWrites(): void
    {
        $written = [
            new Assessment(
                identities: AdvisoryFingerprint::identitiesOf(self::advisoryOn('symfony/http-kernel')),
                component: PackageRef::fromString(self::KERNEL),
                status: Status::NotAffected,
                reason: 'Replaced in production builds.',
                origin: self::origin(),
                issuedAt: new \DateTimeImmutable(AssessmentBuilder::ISSUED_AT),
                justification: Justification::ComponentNotPresent,
            ),
            AssessmentBuilder::falsePositive(self::advisoryOn('@acme/widgets', Ecosystem::Npm), self::WIDGETS),
            new Assessment(
                identities: AdvisoryFingerprint::identitiesOf(self::advisoryOn('guzzlehttp/psr7')),
                component: PackageRef::fromString('pkg:composer/guzzlehttp/psr7@2.4.1'),
                status: Status::Affected,
                reason: 'Rolling back to the release before the regression.',
                origin: self::origin(),
                issuedAt: new \DateTimeImmutable(AssessmentBuilder::ISSUED_AT),
                response: Response::Rollback,
                acceptedSeverity: Severity::Critical,
            ),
            AssessmentBuilder::fixed(self::advisoryOn('monolog/monolog'), 'pkg:composer/monolog/monolog@3.5.0'),
            AssessmentBuilder::underInvestigation(self::advisoryOn('twig/twig'), 'pkg:composer/twig/twig@3.8.0'),
        ];

        $read = $this->writeAndRead($written);

        self::assertEquals(self::byComponent($written), self::byComponent($read));
    }

    #[Test]
    public function readBackAssessmentsStillCoverTheFindingsTheyWereMadeAbout(): void
    {
        $advisory = AdvisoryBuilder::build(
            packageName: 'symfony/http-kernel',
            remoteId: 'GHSA-jfh8-c2jp-5v3q',
            cve: 'CVE-2026-1234',
            severity: Severity::High,
        );
        $finding = new Finding($advisory, PackageRef::fromString(self::KERNEL));
        $matcher = new AssessmentMatcher(FrozenClock::at(self::NOW));

        foreach ([AssessmentBuilder::notAffected($advisory, self::KERNEL), AssessmentBuilder::affected($advisory, self::KERNEL)] as $assessment) {
            $read = $this->writeAndRead([$assessment]);

            self::assertCount(1, $read);
            self::assertTrue($matcher->covers($read[0], $finding), $assessment->status->value);
        }
    }

    #[Test]
    public function keepsTheCaseOfAnNpmNameSoTheStatementStillCoversItsFinding(): void
    {
        $advisory = self::advisoryOn('JSONStream', Ecosystem::Npm);
        $written = AssessmentBuilder::falsePositive($advisory, 'pkg:npm/JSONStream@1.3.5');

        $json = (new CycloneDxVexWriter())->write([$written], ExportScope::All, VexDocumentMetadataBuilder::build());
        $read = $this->writeAndRead([$written]);

        self::assertStringContainsString('"purl": "pkg:npm/JSONStream@1.3.5"', $json);
        self::assertStringContainsString('"name": "JSONStream"', $json);
        self::assertCount(1, $read);
        self::assertTrue(
            (new AssessmentMatcher(FrozenClock::at(self::NOW)))->covers($read[0], new Finding($advisory, PackageRef::fromString('pkg:npm/JSONStream@1.3.5'))),
        );
    }

    /**
     * @param list<Assessment> $assessments
     * @return list<Assessment>
     */
    private function writeAndRead(array $assessments): array
    {
        $clock = FrozenClock::at(self::NOW);
        $json = (new CycloneDxVexWriter())->write($assessments, ExportScope::All, VexDocumentMetadataBuilder::build());

        return (new CycloneDxVexReader(new CycloneDxParser(), $clock))->read($json, self::origin(), null)->assessments;
    }

    /**
     * Named by its CVE and GHSA only: the writer leaves out a feed's own id
     * when a CVE or GHSA names the advisory.
     */
    private static function advisoryOn(string $packageName, Ecosystem $ecosystem = Ecosystem::Composer): Advisory
    {
        return AdvisoryBuilder::build(
            advisoryId: '',
            packageName: $packageName,
            ecosystem: $ecosystem,
            remoteId: 'GHSA-jfh8-c2jp-5v3q',
            cve: 'CVE-2026-1234',
        );
    }

    /**
     * @param list<Assessment> $assessments
     * @return array<string, Assessment>
     */
    private static function byComponent(array $assessments): array
    {
        $indexed = [];
        foreach ($assessments as $assessment) {
            $indexed[$assessment->component->toString()] = $assessment;
        }
        ksort($indexed);

        return $indexed;
    }

    private static function origin(): Origin
    {
        return Origin::user('42');
    }
}
