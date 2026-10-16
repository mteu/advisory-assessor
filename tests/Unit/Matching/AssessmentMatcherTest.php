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

namespace mteu\AdvisoryAssessor\Tests\Unit\Matching;

use mteu\AdvisoryMatcher\Source\PackageRef;
use mteu\AdvisoryAssessor\Matching\Finding;
use mteu\AdvisoryAssessor\Matching\Resolution;
use mteu\AdvisoryAssessor\Matching\AssessmentMatcher;
use mteu\AdvisoryAssessor\Assessment\Assessment;
use mteu\AdvisoryAssessor\Assessment\Status;
use mteu\AdvisoryAssessor\Tests\Unit\Advisory\AdvisoryBuilder;
use mteu\AdvisoryAssessor\Tests\Unit\Clock\FrozenClock;
use mteu\AdvisoryAssessor\Tests\Unit\Assessment\AssessmentBuilder;
use mteu\AdvisoryMatcher\Advisory\Advisory;
use mteu\AdvisoryMatcher\Advisory\Severity;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Truth table for when an assessment covers a finding. The `affected` cases
 * mirror the extension's acknowledgement tests and have to keep passing.
 */
#[CoversClass(AssessmentMatcher::class)]
#[CoversClass(Resolution::class)]
final class AssessmentMatcherTest extends TestCase
{
    private const string NOW = '2026-10-08T12:00:00+00:00';
    private const string INSTALLED = 'pkg:composer/vendor/package@1.4.2';

    #[Test]
    public function anUnexpiredAssessmentCoversTheFindingItWasMadeFor(): void
    {
        $advisory = $this->advisory();

        self::assertTrue($this->matcher()->covers(AssessmentBuilder::affected($advisory, self::INSTALLED), $this->finding($advisory)));
    }

    #[Test]
    public function aAssessmentWithoutExpiryNeverLapses(): void
    {
        $advisory = $this->advisory();

        self::assertTrue(
            $this->matcher('2036-10-08T12:00:00+00:00')->covers(
                AssessmentBuilder::affected($advisory, self::INSTALLED),
                $this->finding($advisory),
            ),
        );
    }

    #[Test]
    public function anExpiredAssessmentCoversNothing(): void
    {
        $advisory = $this->advisory();
        $assessment = AssessmentBuilder::affected($advisory, self::INSTALLED, expiresAt: '2026-10-08T11:59:59+00:00');

        self::assertFalse($this->matcher()->covers($assessment, $this->finding($advisory)));
    }

    #[Test]
    public function aVersionChangeReleasesTheAssessment(): void
    {
        $advisory = $this->advisory();
        $assessment = AssessmentBuilder::notAffected($advisory, self::INSTALLED);

        self::assertFalse($this->matcher()->covers($assessment, $this->finding($advisory, 'pkg:composer/vendor/package@1.5.0')));
    }

    #[Test]
    public function aMixedCaseComposerSpellingStillNamesTheSameComponent(): void
    {
        $advisory = $this->advisory();
        $assessment = AssessmentBuilder::notAffected($advisory, 'pkg:composer/Vendor/Package@1.4.2');

        self::assertTrue($this->matcher()->covers($assessment, $this->finding($advisory)));
    }

    #[Test]
    public function anEscalatedSeverityReleasesAnAffectedAssessment(): void
    {
        $assessment = AssessmentBuilder::affected($this->advisory(severity: Severity::Medium), self::INSTALLED);

        $rescored = $this->advisory(severity: Severity::Critical);

        self::assertFalse($this->matcher()->covers($assessment, $this->finding($rescored)));
    }

    #[Test]
    public function aDowngradedSeverityLeavesAnAffectedAssessmentStanding(): void
    {
        $assessment = AssessmentBuilder::affected($this->advisory(severity: Severity::High), self::INSTALLED);

        $rescored = $this->advisory(severity: Severity::Low);

        self::assertTrue($this->matcher()->covers($assessment, $this->finding($rescored)));
    }

    #[Test]
    public function anEscalatedSeverityLeavesANotAffectedAssessmentStanding(): void
    {
        // Unreachable code stays unreachable, however the advisory is scored.
        $assessment = AssessmentBuilder::notAffected($this->advisory(severity: Severity::Low), self::INSTALLED);

        $rescored = $this->advisory(severity: Severity::Critical);

        self::assertTrue($this->matcher()->covers($assessment, $this->finding($rescored)));
    }

    #[Test]
    public function aFindingWhoseCveWasBackfilledStaysCovered(): void
    {
        $assessment = AssessmentBuilder::affected($this->advisory(cve: ''), self::INSTALLED);

        $backfilled = $this->advisory(cve: 'CVE-2024-1234');

        self::assertTrue($this->matcher()->covers($assessment, $this->finding($backfilled)));
    }

    #[Test]
    public function anUnrelatedFindingOfTheSamePackageIsNotCovered(): void
    {
        $assessment = AssessmentBuilder::notAffected($this->advisory(), self::INSTALLED);

        $other = $this->advisory(advisoryId: 'PKSA-9999-9999-9999', cve: 'CVE-2025-4321');

        self::assertFalse($this->matcher()->covers($assessment, $this->finding($other)));
    }

    #[Test]
    public function aFindingWithoutAnyAssessmentStaysVisible(): void
    {
        $resolution = $this->matcher()->resolve($this->finding($this->advisory()), []);

        self::assertFalse($resolution->hasAssessment());
        self::assertFalse($resolution->isHidden());
    }

    #[Test]
    public function aAssessmentUnderInvestigationClaimsTheFindingWithoutHidingIt(): void
    {
        $advisory = $this->advisory();

        $resolution = $this->matcher()->resolve(
            $this->finding($advisory),
            [AssessmentBuilder::underInvestigation($advisory, self::INSTALLED)],
        );

        self::assertTrue($resolution->hasAssessment());
        self::assertFalse($resolution->isHidden());
    }

    /**
     * @return iterable<string, array{list<string>, Status, bool}>
     */
    public static function competingAssessments(): iterable
    {
        yield 'under_investigation beats not_affected' => [['notAffected', 'underInvestigation'], Status::UnderInvestigation, false];
        yield 'affected beats fixed' => [['fixed', 'affected'], Status::Affected, true];
        yield 'fixed beats not_affected' => [['notAffected', 'fixed'], Status::Fixed, true];
        yield 'not_affected beats false_positive' => [['falsePositive', 'notAffected'], Status::NotAffected, true];
        yield 'under_investigation beats everything' => [
            ['falsePositive', 'notAffected', 'fixed', 'affected', 'underInvestigation'],
            Status::UnderInvestigation,
            false,
        ];
    }

    /**
     * @param list<string> $kinds names of AssessmentBuilder factories
     */
    #[Test]
    #[DataProvider('competingAssessments')]
    public function theMostAlarmingCoveringAssessmentDecides(array $kinds, Status $decisive, bool $hidden): void
    {
        $advisory = $this->advisory();
        $assessments = array_map(
            static fn (string $kind): Assessment => match ($kind) {
                'notAffected' => AssessmentBuilder::notAffected($advisory, self::INSTALLED),
                'falsePositive' => AssessmentBuilder::falsePositive($advisory, self::INSTALLED),
                'affected' => AssessmentBuilder::affected($advisory, self::INSTALLED),
                'fixed' => AssessmentBuilder::fixed($advisory, self::INSTALLED),
                'underInvestigation' => AssessmentBuilder::underInvestigation($advisory, self::INSTALLED),
                default => throw new \LogicException('No such assessment kind: ' . $kind),
            },
            $kinds,
        );

        $resolution = $this->matcher()->resolve($this->finding($advisory), $assessments);

        self::assertSame($decisive, $resolution->covering[0]->status);
        self::assertSame($hidden, $resolution->isHidden());
    }

    #[Test]
    public function aAssessmentThatNoLongerCoversDoesNotCompete(): void
    {
        $advisory = $this->advisory();

        $resolution = $this->matcher()->resolve(
            $this->finding($advisory),
            [
                AssessmentBuilder::affected($advisory, self::INSTALLED, expiresAt: '2026-10-08T00:00:00+00:00'),
                AssessmentBuilder::notAffected($advisory, self::INSTALLED),
            ],
        );

        self::assertCount(1, $resolution->covering);
        self::assertSame(Status::NotAffected, $resolution->covering[0]->status);
        self::assertTrue($resolution->isHidden());
    }

    #[Test]
    #[Group('performance')]
    public function resolvesThousandsOfFindingsAgainstThousandsOfAssessmentsQuickly(): void
    {
        $advisories = [];
        $assessments = [];
        for ($i = 0; $i < 1500; $i++) {
            $advisories[] = $this->advisory(advisoryId: sprintf('PKSA-%d', $i), cve: sprintf('CVE-2026-%05d', $i));
            $assessments[] = AssessmentBuilder::notAffected($advisories[$i], self::INSTALLED);
        }
        $matcher = $this->matcher();

        $startedAt = hrtime(true);
        $hidden = 0;
        foreach ($advisories as $advisory) {
            $hidden += $matcher->resolve($this->finding($advisory), $assessments)->isHidden() ? 1 : 0;
        }
        $seconds = (hrtime(true) - $startedAt) / 1e9;

        self::assertSame(1500, $hidden);
        // Rebuilding both package URLs on every comparison took about 15 s
        // here, comparing their canonical strings about 1.3 s.
        self::assertLessThan(10.0, $seconds);
    }

    private function matcher(string $now = self::NOW): AssessmentMatcher
    {
        return new AssessmentMatcher(FrozenClock::at($now));
    }

    private function finding(Advisory $advisory, string $purl = self::INSTALLED): Finding
    {
        return new Finding($advisory, PackageRef::fromString($purl));
    }

    private function advisory(
        string $advisoryId = 'PKSA-1111-2222-3333',
        string $cve = '',
        Severity $severity = Severity::Medium,
    ): Advisory {
        return AdvisoryBuilder::build(advisoryId: $advisoryId, cve: $cve, severity: $severity);
    }
}
