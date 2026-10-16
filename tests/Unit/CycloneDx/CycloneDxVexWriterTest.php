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
use mteu\AdvisoryAssessor\CycloneDx\ContradictingAssessments;
use mteu\AdvisoryAssessor\CycloneDx\CycloneDxVexWriter;
use mteu\AdvisoryAssessor\CycloneDx\ExportScope;
use mteu\AdvisoryAssessor\CycloneDx\IdentityKind;
use mteu\AdvisoryAssessor\CycloneDx\UnexportableAssessments;
use mteu\AdvisoryAssessor\CycloneDx\VulnerabilityId;
use mteu\AdvisoryAssessor\Assessment\Justification;
use mteu\AdvisoryAssessor\Assessment\Origin;
use mteu\AdvisoryAssessor\Assessment\Response;
use mteu\AdvisoryAssessor\Assessment\Assessment;
use mteu\AdvisoryAssessor\Assessment\Status;
use mteu\AdvisoryAssessor\Document\Author;
use mteu\AdvisoryAssessor\Document\VexDocumentMetadata;
use mteu\AdvisoryAssessor\Tests\Unit\Advisory\AdvisoryBuilder;
use mteu\AdvisoryAssessor\Tests\Unit\Document\VexDocumentMetadataBuilder;
use mteu\AdvisoryAssessor\Tests\Unit\Assessment\AssessmentBuilder;
use mteu\AdvisoryMatcher\Advisory\Advisory;
use mteu\AdvisoryMatcher\Advisory\AdvisoryFingerprint;
use mteu\AdvisoryMatcher\Advisory\Severity;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(CycloneDxVexWriter::class)]
#[CoversClass(UnexportableAssessments::class)]
#[CoversClass(ContradictingAssessments::class)]
#[CoversClass(VulnerabilityId::class)]
#[CoversClass(IdentityKind::class)]
final class CycloneDxVexWriterTest extends TestCase
{
    private const string PURL = 'pkg:composer/symfony/http-kernel@5.4.19';

    private const string OTHER_PURL = 'pkg:composer/guzzlehttp/psr7@2.4.1';

    private const string CVE = 'CVE-2026-1234';

    private const string GHSA = 'GHSA-jfh8-c2jp-5v3q';

    /**
     * @return iterable<string, array{Assessment, string}>
     */
    public static function assessmentsAndTheirState(): iterable
    {
        $advisory = self::advisory();

        yield 'not_affected' => [AssessmentBuilder::notAffected($advisory, self::PURL), 'not_affected'];
        yield 'false_positive' => [AssessmentBuilder::falsePositive($advisory, self::PURL), 'false_positive'];
        yield 'affected' => [AssessmentBuilder::affected($advisory, self::PURL), 'exploitable'];
        yield 'fixed, without a pedigree to back resolved_with_pedigree' => [AssessmentBuilder::fixed($advisory, self::PURL), 'resolved'];
        yield 'under_investigation' => [AssessmentBuilder::underInvestigation($advisory, self::PURL), 'in_triage'];
    }

    /**
     * @return iterable<string, array{Justification, string}>
     */
    public static function justificationsAndTheirCycloneDxValue(): iterable
    {
        foreach (Justification::cases() as $justification) {
            yield $justification->value => [
                $justification,
                $justification === Justification::ComponentNotPresent ? 'code_not_present' : $justification->value,
            ];
        }
    }

    /**
     * @return iterable<string, array{Response}>
     */
    public static function responses(): iterable
    {
        foreach (Response::cases() as $response) {
            yield $response->value => [$response];
        }
    }

    #[Test]
    public function writesASchemaValidCycloneDx16DocumentHoldingEveryStatus(): void
    {
        $json = $this->writer()->write($this->oneAssessmentPerStatus(), ExportScope::All, VexDocumentMetadataBuilder::build());

        self::assertSame([], CycloneDxSchema::findViolations($json));

        $document = self::decode($json);
        self::assertSame('CycloneDX', $document['bomFormat']);
        self::assertSame('1.6', $document['specVersion']);
        self::assertCount(5, self::listAt($document, 'vulnerabilities'));
    }

    #[Test]
    public function carriesTheDocumentIdAsSerialNumberAndTheDocumentVersion(): void
    {
        $document = self::decode($this->writer()->write(
            $this->oneAssessmentPerStatus(),
            ExportScope::All,
            new VexDocumentMetadata(
                documentId: '3E671687-395B-41F5-A30F-A58921A69B79',
                version: 7,
                author: Author::organization(VexDocumentMetadataBuilder::AUTHOR),
                issuedAt: new \DateTimeImmutable(VexDocumentMetadataBuilder::ISSUED_AT),
            ),
        ));

        self::assertSame('urn:uuid:' . VexDocumentMetadataBuilder::DOCUMENT_ID, $document['serialNumber']);
        self::assertSame(7, $document['version']);
    }

    #[Test]
    public function writesTheDocumentIssueTimeInUtcAsTheTimestamp(): void
    {
        $document = self::decode($this->writer()->write(
            [AssessmentBuilder::fixed(self::advisory(), self::PURL)],
            ExportScope::All,
            VexDocumentMetadataBuilder::build(issuedAt: '2026-10-08T14:30:00+02:00'),
        ));

        self::assertIsArray($document['metadata']);
        self::assertSame('2026-10-08T12:30:00Z', $document['metadata']['timestamp']);
    }

    #[Test]
    public function writesAnOrganizationAsTheManufacturerOfTheDocument(): void
    {
        $json = $this->writer()->write([], ExportScope::All, VexDocumentMetadataBuilder::build());

        self::assertSame([], CycloneDxSchema::findViolations($json));
        self::assertSame(
            ['timestamp' => '2026-10-08T12:30:00Z', 'manufacturer' => ['name' => VexDocumentMetadataBuilder::AUTHOR]],
            self::decode($json)['metadata'],
        );
    }

    #[Test]
    public function writesAPersonAsTheAuthorOfTheDocument(): void
    {
        $json = $this->writer()->write(
            [],
            ExportScope::All,
            new VexDocumentMetadata(
                documentId: VexDocumentMetadataBuilder::DOCUMENT_ID,
                version: 1,
                author: Author::person('Jane Doe'),
                issuedAt: new \DateTimeImmutable(VexDocumentMetadataBuilder::ISSUED_AT),
            ),
        );

        self::assertSame([], CycloneDxSchema::findViolations($json));
        self::assertSame(
            ['timestamp' => '2026-10-08T12:30:00Z', 'authors' => [['name' => 'Jane Doe']]],
            self::decode($json)['metadata'],
        );
    }

    #[Test]
    public function refusesADocumentIssuedBeforeAnAssessmentItCarries(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->writer()->write(
            [AssessmentBuilder::fixed(self::advisory(), self::PURL)],
            ExportScope::All,
            VexDocumentMetadataBuilder::build(issuedAt: '2026-09-30T23:59:59+00:00'),
        );
    }

    #[Test]
    public function acceptsADocumentIssuedAtTheSameTimeAsItsNewestAssessment(): void
    {
        $json = $this->writer()->write(
            [AssessmentBuilder::fixed(self::advisory(), self::PURL)],
            ExportScope::All,
            VexDocumentMetadataBuilder::build(issuedAt: AssessmentBuilder::ISSUED_AT),
        );

        self::assertSame([], CycloneDxSchema::findViolations($json));
    }

    #[Test]
    public function ignoresTheIssueTimeOfAssessmentsTheScopeLeavesOut(): void
    {
        $json = $this->writer()->write(
            [AssessmentBuilder::affected(self::advisory(), self::PURL)],
            ExportScope::ResolvedOnly,
            VexDocumentMetadataBuilder::build(issuedAt: '2026-09-30T23:59:59+00:00'),
        );

        self::assertSame([], self::listAt(self::decode($json), 'vulnerabilities'));
    }

    #[Test]
    #[DataProvider('assessmentsAndTheirState')]
    public function mapsEachStatusToItsCycloneDxState(Assessment $assessment, string $expectedState): void
    {
        $analysis = self::onlyVulnerability($this->writer()->write([$assessment], ExportScope::All, VexDocumentMetadataBuilder::build()))['analysis'];

        self::assertIsArray($analysis);
        self::assertSame($expectedState, $analysis['state']);
    }

    #[Test]
    #[DataProvider('justificationsAndTheirCycloneDxValue')]
    public function writesEveryJustificationAsAValueTheSchemaAccepts(Justification $justification, string $expected): void
    {
        $json = $this->writer()->write([$this->notAffectedBecause($justification)], ExportScope::All, VexDocumentMetadataBuilder::build());

        self::assertSame([], CycloneDxSchema::findViolations($json));
        $analysis = self::onlyVulnerability($json)['analysis'];
        self::assertIsArray($analysis);
        self::assertSame($expected, $analysis['justification']);
    }

    #[Test]
    #[DataProvider('responses')]
    public function writesEveryResponseAsAValueTheSchemaAccepts(Response $response): void
    {
        $json = $this->writer()->write(
            [$this->affectedWith($response)],
            ExportScope::All,
            VexDocumentMetadataBuilder::build(),
        );

        self::assertSame([], CycloneDxSchema::findViolations($json));
        $analysis = self::onlyVulnerability($json)['analysis'];
        self::assertIsArray($analysis);
        self::assertSame([$response->value], $analysis['response']);
    }

    #[Test]
    public function keepsComponentNotPresentReadableBesideTheNearestCycloneDxJustification(): void
    {
        $vulnerability = self::onlyVulnerability($this->writer()->write(
            [$this->notAffectedBecause(Justification::ComponentNotPresent)],
            ExportScope::All,
            VexDocumentMetadataBuilder::build(),
        ));

        self::assertSame(
            [['name' => CycloneDxVexWriter::JUSTIFICATION_PROPERTY, 'value' => 'component_not_present']],
            $vulnerability['properties'],
        );
    }

    #[Test]
    public function writesNoPropertiesForAJustificationCycloneDxHas(): void
    {
        $vulnerability = self::onlyVulnerability($this->writer()->write(
            [$this->notAffectedBecause(Justification::CodeNotPresent)],
            ExportScope::All,
            VexDocumentMetadataBuilder::build(),
        ));

        self::assertArrayNotHasKey('properties', $vulnerability);
    }

    #[Test]
    public function leavesAffectedAndUnderInvestigationOutOfAResolvedOnlyExport(): void
    {
        $vulnerabilities = self::listAt(
            self::decode($this->writer()->write($this->oneAssessmentPerStatus(), ExportScope::ResolvedOnly, VexDocumentMetadataBuilder::build())),
            'vulnerabilities',
        );

        $states = [];
        foreach ($vulnerabilities as $vulnerability) {
            self::assertIsArray($vulnerability);
            self::assertIsArray($vulnerability['analysis']);
            $states[] = $vulnerability['analysis']['state'];
        }
        sort($states);

        self::assertSame(['false_positive', 'not_affected', 'resolved'], $states);
    }

    #[Test]
    public function namesTheVulnerabilityByItsCveAndReferencesItsGhsa(): void
    {
        $vulnerability = self::onlyVulnerability($this->writer()->write(
            [AssessmentBuilder::falsePositive(self::advisory(), self::PURL)],
            ExportScope::All,
            VexDocumentMetadataBuilder::build(),
        ));

        self::assertSame(self::CVE, $vulnerability['id']);
        self::assertSame(['name' => 'NVD', 'url' => 'https://nvd.nist.gov/vuln/detail/' . self::CVE], $vulnerability['source']);
        self::assertSame(
            [['id' => self::GHSA, 'source' => ['name' => 'GitHub', 'url' => 'https://github.com/advisories/' . self::GHSA]]],
            $vulnerability['references'],
        );
    }

    #[Test]
    public function fallsBackToTheGhsaWhenAnAdvisoryHasNoCve(): void
    {
        $vulnerability = self::onlyVulnerability($this->writer()->write(
            [AssessmentBuilder::falsePositive(self::advisory(cve: ''), self::PURL)],
            ExportScope::All,
            VexDocumentMetadataBuilder::build(),
        ));

        self::assertSame(self::GHSA, $vulnerability['id']);
        self::assertSame(['name' => 'GitHub', 'url' => 'https://github.com/advisories/' . self::GHSA], $vulnerability['source']);
        self::assertArrayNotHasKey('references', $vulnerability);
    }

    #[Test]
    public function fallsBackToTheFeedsOwnIdWithoutClaimingASource(): void
    {
        $vulnerability = self::onlyVulnerability($this->writer()->write(
            [AssessmentBuilder::falsePositive(self::advisory(cve: '', remoteId: ''), self::PURL)],
            ExportScope::All,
            VexDocumentMetadataBuilder::build(),
        ));

        self::assertSame('PKSA-1111-2222-3333', $vulnerability['id']);
        self::assertArrayNotHasKey('source', $vulnerability);
    }

    #[Test]
    public function refusesAAssessmentNamedOnlyByAHashNoOtherToolCanRead(): void
    {
        $assessment = AssessmentBuilder::falsePositive(self::advisory(advisoryId: '', cve: '', remoteId: ''), self::PURL);

        self::assertFalse($this->writer()->canWrite($assessment));

        try {
            $this->writer()->write([$assessment], ExportScope::All, VexDocumentMetadataBuilder::build());
            self::fail('A hash-only assessment was written.');
        } catch (UnexportableAssessments $exception) {
            self::assertSame([$assessment], $exception->assessments);
        }
    }

    #[Test]
    public function refusesAHashOnlyAssessmentAsASingleVulnerabilityToo(): void
    {
        $this->expectException(UnexportableAssessments::class);

        $this->writer()->writeVulnerability(
            AssessmentBuilder::falsePositive(self::advisory(advisoryId: '', cve: '', remoteId: ''), self::PURL),
        );
    }

    #[Test]
    public function ignoresHashOnlyAssessmentsTheScopeLeavesOutAnyway(): void
    {
        $hashOnly = AssessmentBuilder::affected(self::advisory(advisoryId: '', cve: '', remoteId: ''), self::PURL);

        $json = $this->writer()->write([$hashOnly], ExportScope::ResolvedOnly, VexDocumentMetadataBuilder::build());

        self::assertSame([], self::listAt(self::decode($json), 'vulnerabilities'));
    }

    #[Test]
    public function refusesTwoAssessmentsAboutOneAdvisoryOnOneComponent(): void
    {
        $notAffected = AssessmentBuilder::notAffected(self::advisory(), self::PURL);
        $falsePositive = AssessmentBuilder::falsePositive(self::advisory(cve: ''), self::PURL);

        try {
            $this->writer()->write([$notAffected, $falsePositive], ExportScope::All, VexDocumentMetadataBuilder::build());
            self::fail('Two assessments about one advisory on one component were written.');
        } catch (ContradictingAssessments $exception) {
            self::assertSame([$notAffected, $falsePositive], $exception->assessments);
        }
    }

    #[Test]
    public function namesEveryContradictingAssessmentOnceInTheOrderGivenAndNoOther(): void
    {
        $kernelNotAffected = AssessmentBuilder::notAffected(self::advisory(), self::PURL);
        $psr7NotAffected = AssessmentBuilder::notAffected(self::advisory(), self::OTHER_PURL);
        $kernelFixed = AssessmentBuilder::fixed(self::advisory(), self::PURL);
        $kernelFalsePositive = AssessmentBuilder::falsePositive(self::advisory(remoteId: ''), self::PURL);

        try {
            $this->writer()->write(
                [$kernelNotAffected, $psr7NotAffected, $kernelFixed, $kernelFalsePositive],
                ExportScope::All,
                VexDocumentMetadataBuilder::build(),
            );
            self::fail('Contradicting assessments were written.');
        } catch (ContradictingAssessments $exception) {
            self::assertSame([$kernelNotAffected, $kernelFixed, $kernelFalsePositive], $exception->assessments);
        }
    }

    #[Test]
    public function writesTwoAssessmentsAboutOneAdvisoryWhenTheScopeLeavesOneOut(): void
    {
        $json = $this->writer()->write(
            [
                AssessmentBuilder::fixed(self::advisory(), self::PURL),
                AssessmentBuilder::underInvestigation(self::advisory(), self::PURL),
            ],
            ExportScope::ResolvedOnly,
            VexDocumentMetadataBuilder::build(),
        );

        self::assertCount(1, self::listAt(self::decode($json), 'vulnerabilities'));
    }

    #[Test]
    public function writesOneVulnerabilityPerComponentWhenAnAdvisoryHitsTwo(): void
    {
        $document = self::decode($this->writer()->write(
            [
                AssessmentBuilder::notAffected(self::advisory(), self::PURL),
                AssessmentBuilder::falsePositive(self::advisory(), self::OTHER_PURL),
            ],
            ExportScope::All,
            VexDocumentMetadataBuilder::build(),
        ));

        $refs = [];
        foreach (self::listAt($document, 'vulnerabilities') as $vulnerability) {
            self::assertIsArray($vulnerability);
            self::assertSame(self::CVE, $vulnerability['id']);
            $refs[] = $vulnerability['affects'];
        }

        self::assertSame([[['ref' => self::OTHER_PURL]], [['ref' => self::PURL]]], $refs);
        self::assertCount(2, self::listAt($document, 'components'));
    }

    #[Test]
    public function repeatsEachComponentOnceWithItsPurlAsBomRef(): void
    {
        $document = self::decode($this->writer()->write(
            [
                AssessmentBuilder::notAffected(self::advisory(), self::PURL),
                AssessmentBuilder::falsePositive(self::advisory(advisoryId: 'PKSA-9999-9999-9999', cve: 'CVE-2026-9999', remoteId: ''), self::PURL),
            ],
            ExportScope::All,
            VexDocumentMetadataBuilder::build(),
        ));

        self::assertSame(
            [[
                'type' => 'library',
                'bom-ref' => self::PURL,
                'group' => 'symfony',
                'name' => 'http-kernel',
                'version' => '5.4.19',
                'purl' => self::PURL,
            ]],
            $document['components'],
        );
    }

    #[Test]
    public function writesNoGroupForAPackageWithoutNamespace(): void
    {
        $document = self::decode($this->writer()->write(
            [AssessmentBuilder::falsePositive(self::advisory(), 'pkg:npm/lodash@4.17.20')],
            ExportScope::All,
            VexDocumentMetadataBuilder::build(),
        ));

        $components = self::listAt($document, 'components');
        self::assertIsArray($components[0]);
        self::assertArrayNotHasKey('group', $components[0]);
    }

    #[Test]
    public function writesTheSameDocumentWhateverOrderTheAssessmentsArriveIn(): void
    {
        $assessments = [
            AssessmentBuilder::notAffected(self::advisory(), self::PURL),
            AssessmentBuilder::falsePositive(self::advisory(), self::OTHER_PURL),
            AssessmentBuilder::fixed(self::advisory(advisoryId: 'PKSA-0001-0001-0001', cve: 'CVE-2026-0001', remoteId: ''), self::PURL),
        ];

        self::assertSame(
            $this->writer()->write($assessments, ExportScope::All, VexDocumentMetadataBuilder::build()),
            $this->writer()->write(array_reverse($assessments), ExportScope::All, VexDocumentMetadataBuilder::build()),
        );
    }

    #[Test]
    public function keepsOriginAndExpiryInternal(): void
    {
        $assessment = new Assessment(
            identities: AdvisoryFingerprint::identitiesOf(self::advisory()),
            component: PackageRef::fromString(self::PURL),
            status: Status::Affected,
            reason: 'Accepted until the next release.',
            origin: Origin::user('origin-must-stay-internal'),
            issuedAt: new \DateTimeImmutable(AssessmentBuilder::ISSUED_AT),
            response: Response::Update,
            acceptedSeverity: Severity::Critical,
            expiresAt: new \DateTimeImmutable('2031-07-07T00:00:00+00:00'),
        );

        $json = $this->writer()->write([$assessment], ExportScope::All, VexDocumentMetadataBuilder::build());

        self::assertStringNotContainsString('origin-must-stay-internal', $json);
        self::assertStringNotContainsString('2031', $json);
    }

    #[Test]
    public function writesTheAcceptedSeverityOfAnAffectedAssessmentAsAProperty(): void
    {
        $json = $this->writer()->write([$this->affectedWith(Response::Update)], ExportScope::All, VexDocumentMetadataBuilder::build());

        self::assertSame([], CycloneDxSchema::findViolations($json));
        self::assertSame(
            [['name' => CycloneDxVexWriter::ACCEPTED_SEVERITY_PROPERTY, 'value' => 'high']],
            self::onlyVulnerability($json)['properties'],
        );
    }

    #[Test]
    public function writesNoAcceptedSeverityForAStatusThatAcceptsNone(): void
    {
        $vulnerability = self::onlyVulnerability($this->writer()->write(
            [AssessmentBuilder::fixed(self::advisory(), self::PURL)],
            ExportScope::All,
            VexDocumentMetadataBuilder::build(),
        ));

        self::assertArrayNotHasKey('properties', $vulnerability);
    }

    #[Test]
    public function writesTheReasonAsDetailAndTheIssueTimeInUtc(): void
    {
        $assessment = new Assessment(
            identities: AdvisoryFingerprint::identitiesOf(self::advisory()),
            component: PackageRef::fromString(self::PURL),
            status: Status::NotAffected,
            reason: 'Fragments are never rendered, so the vulnerable path is never called.',
            origin: Origin::user('42'),
            issuedAt: new \DateTimeImmutable('2026-10-01T09:15:00+02:00'),
            justification: Justification::CodeNotReachable,
        );

        $analysis = self::onlyVulnerability($this->writer()->write([$assessment], ExportScope::All, VexDocumentMetadataBuilder::build()))['analysis'];

        self::assertSame(
            [
                'state' => 'not_affected',
                'justification' => 'code_not_reachable',
                'detail' => 'Fragments are never rendered, so the vulnerable path is never called.',
                'firstIssued' => '2026-10-01T07:15:00Z',
                'lastUpdated' => '2026-10-01T07:15:00Z',
            ],
            $analysis,
        );
    }

    #[Test]
    public function writesNoDetailForAAssessmentStillUnderInvestigation(): void
    {
        $analysis = self::onlyVulnerability($this->writer()->write(
            [AssessmentBuilder::underInvestigation(self::advisory(), self::PURL)],
            ExportScope::All,
            VexDocumentMetadataBuilder::build(),
        ))['analysis'];

        self::assertIsArray($analysis);
        self::assertArrayNotHasKey('detail', $analysis);
    }

    #[Test]
    public function writesAValidEmptyDocumentForNoAssessments(): void
    {
        $json = $this->writer()->write([], ExportScope::ResolvedOnly, VexDocumentMetadataBuilder::build());

        self::assertSame([], CycloneDxSchema::findViolations($json));
        self::assertSame([], self::listAt(self::decode($json), 'vulnerabilities'));
    }

    #[Test]
    public function writesASingleAssessmentAsTheVulnerabilityObjectToPasteIntoARepository(): void
    {
        $json = $this->writer()->writeVulnerability(AssessmentBuilder::notAffected(self::advisory(), self::PURL));

        $expected = <<<'JSON'
            {
                "id": "CVE-2026-1234",
                "source": {
                    "name": "NVD",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1234"
                },
                "references": [
                    {
                        "id": "GHSA-jfh8-c2jp-5v3q",
                        "source": {
                            "name": "GitHub",
                            "url": "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q"
                        }
                    }
                ],
                "analysis": {
                    "state": "not_affected",
                    "justification": "code_not_reachable",
                    "detail": "Assessed by the team.",
                    "firstIssued": "2026-10-01T00:00:00Z",
                    "lastUpdated": "2026-10-01T00:00:00Z"
                },
                "affects": [
                    {
                        "ref": "pkg:composer/symfony/http-kernel@5.4.19"
                    }
                ]
            }

            JSON;

        self::assertSame($expected, $json);
    }

    private function writer(): CycloneDxVexWriter
    {
        return new CycloneDxVexWriter();
    }

    /**
     * @return list<Assessment>
     */
    private function oneAssessmentPerStatus(): array
    {
        $assessments = [];
        foreach (self::assessmentsAndTheirState() as [$assessment]) {
            $assessments[] = $assessment;
        }

        // One status per advisory, so no two assessments contradict each other.
        foreach ($assessments as $index => $assessment) {
            $assessments[$index] = new Assessment(
                identities: AdvisoryFingerprint::identitiesOf(self::advisory(advisoryId: sprintf('PKSA-0000-0000-000%d', $index), cve: sprintf('CVE-2026-100%d', $index), remoteId: '')),
                component: $assessment->component,
                status: $assessment->status,
                reason: $assessment->reason,
                origin: $assessment->origin,
                issuedAt: $assessment->issuedAt,
                justification: $assessment->justification,
                response: $assessment->response,
                acceptedSeverity: $assessment->acceptedSeverity,
            );
        }

        return $assessments;
    }

    private function notAffectedBecause(Justification $justification): Assessment
    {
        return new Assessment(
            identities: AdvisoryFingerprint::identitiesOf(self::advisory()),
            component: PackageRef::fromString(self::PURL),
            status: Status::NotAffected,
            reason: 'Assessed by the team.',
            origin: Origin::user('42'),
            issuedAt: new \DateTimeImmutable(AssessmentBuilder::ISSUED_AT),
            justification: $justification,
        );
    }

    private function affectedWith(Response $response): Assessment
    {
        return new Assessment(
            identities: AdvisoryFingerprint::identitiesOf(self::advisory()),
            component: PackageRef::fromString(self::PURL),
            status: Status::Affected,
            reason: 'Assessed by the team.',
            origin: Origin::user('42'),
            issuedAt: new \DateTimeImmutable(AssessmentBuilder::ISSUED_AT),
            response: $response,
            acceptedSeverity: Severity::High,
        );
    }

    private static function advisory(string $advisoryId = 'PKSA-1111-2222-3333', string $cve = self::CVE, string $remoteId = self::GHSA): Advisory
    {
        return AdvisoryBuilder::build(
            advisoryId: $advisoryId,
            packageName: 'symfony/http-kernel',
            remoteId: $remoteId,
            cve: $cve,
        );
    }

    /**
     * @return array<array-key, mixed> decoded JSON, whose shape is what is under test
     */
    private static function decode(string $json): array
    {
        $decoded = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);

        return $decoded;
    }

    /**
     * @param array<array-key, mixed> $document
     * @return list<mixed> decoded JSON, whose shape is what is under test
     */
    private static function listAt(array $document, string $key): array
    {
        $list = $document[$key] ?? null;
        self::assertIsArray($list);
        self::assertTrue(array_is_list($list));

        return $list;
    }

    /**
     * @return array<array-key, mixed> decoded JSON, whose shape is what is under test
     */
    private static function onlyVulnerability(string $json): array
    {
        $vulnerabilities = self::listAt(self::decode($json), 'vulnerabilities');
        self::assertCount(1, $vulnerabilities);
        self::assertIsArray($vulnerabilities[0]);

        return $vulnerabilities[0];
    }
}
