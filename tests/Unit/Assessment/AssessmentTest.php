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

namespace mteu\AdvisoryAssessor\Tests\Unit\Assessment;

use mteu\AdvisoryMatcher\Package\PackageUrl;
use mteu\AdvisoryMatcher\Source\PackageRef;
use mteu\AdvisoryAssessor\Assessment\Justification;
use mteu\AdvisoryAssessor\Assessment\Origin;
use mteu\AdvisoryAssessor\Assessment\Response;
use mteu\AdvisoryAssessor\Assessment\Assessment;
use mteu\AdvisoryAssessor\Assessment\Status;
use mteu\AdvisoryMatcher\Advisory\Severity;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;

#[CoversClass(Assessment::class)]
final class AssessmentTest extends TestCase
{
    /**
     * @return iterable<string, array{Status, Justification|null, Response|null, Severity|null}>
     */
    public static function wellFormedStatusFields(): iterable
    {
        yield 'not_affected with a justification' => [Status::NotAffected, Justification::CodeNotReachable, null, null];
        yield 'false_positive bare' => [Status::FalsePositive, null, null, null];
        yield 'affected with response and accepted severity' => [Status::Affected, null, Response::WillNotFix, Severity::Medium];
        yield 'fixed bare' => [Status::Fixed, null, null, null];
        yield 'under_investigation bare' => [Status::UnderInvestigation, null, null, null];
    }

    /**
     * @return iterable<string, array{Status, Justification|null, Response|null, Severity|null}>
     */
    public static function malformedStatusFields(): iterable
    {
        yield 'not_affected without a justification' => [Status::NotAffected, null, null, null];
        yield 'affected with a justification' => [Status::Affected, Justification::CodeNotPresent, Response::WillNotFix, Severity::Medium];
        yield 'fixed with a justification' => [Status::Fixed, Justification::CodeNotPresent, null, null];
        yield 'affected without a response' => [Status::Affected, null, null, Severity::Medium];
        yield 'not_affected with a response' => [Status::NotAffected, Justification::CodeNotPresent, Response::Update, null];
        yield 'affected without an accepted severity' => [Status::Affected, null, Response::WillNotFix, null];
        yield 'false_positive with an accepted severity' => [Status::FalsePositive, null, null, Severity::Low];
    }

    #[Test]
    #[DataProvider('wellFormedStatusFields')]
    public function acceptsTheFieldsItsStatusAsksFor(
        Status $status,
        ?Justification $justification,
        ?Response $response,
        ?Severity $acceptedSeverity,
    ): void {
        $assessment = $this->assessment(
            status: $status,
            justification: $justification,
            response: $response,
            acceptedSeverity: $acceptedSeverity,
        );

        self::assertSame($status, $assessment->status);
    }

    #[Test]
    #[DataProvider('malformedStatusFields')]
    public function rejectsFieldsItsStatusDoesNotAllow(
        Status $status,
        ?Justification $justification,
        ?Response $response,
        ?Severity $acceptedSeverity,
    ): void {
        $this->expectException(\InvalidArgumentException::class);

        $this->assessment(
            status: $status,
            justification: $justification,
            response: $response,
            acceptedSeverity: $acceptedSeverity,
        );
    }

    #[Test]
    public function aAssessmentOtherThanUnderInvestigationNeedsAReason(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->assessment(status: Status::Fixed, reason: '   ');
    }

    #[Test]
    public function aAssessmentUnderInvestigationNeedsNoReason(): void
    {
        self::assertSame('', $this->assessment(status: Status::UnderInvestigation, reason: '')->reason);
    }

    #[Test]
    public function aAssessmentCannotExpireBeforeItWasIssued(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->assessment(expiresAt: new \DateTimeImmutable(AssessmentBuilder::ISSUED_AT));
    }

    #[Test]
    public function aAssessmentHasToNameTheAdvisory(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->assessment(identities: []);
    }

    #[Test]
    public function aAssessmentRejectsABlankIdentity(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->assessment(identities: ['composer|vendor/package|cve|CVE-2026-1234', ' ']);
    }

    #[Test]
    public function aAssessmentWithoutExpiryNeverExpires(): void
    {
        self::assertFalse($this->assessment()->isExpiredAt(new \DateTimeImmutable('2126-01-01T00:00:00+00:00')));
    }

    #[Test]
    public function aAssessmentExpiresAtTheMomentItsExpiryIsReached(): void
    {
        $expiresAt = new \DateTimeImmutable('2026-12-31T00:00:00+00:00');
        $assessment = $this->assessment(expiresAt: $expiresAt);

        self::assertFalse($assessment->isExpiredAt($expiresAt->modify('-1 second')));
        self::assertTrue($assessment->isExpiredAt($expiresAt));
    }

    #[Test]
    #[TestWith([''])]
    #[TestWith(['   '])]
    public function refusesAComponentWithoutAVersion(string $version): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new Assessment(
            identities: ['composer|vendor/package|cve|CVE-2026-1234'],
            component: new PackageRef(PackageUrl::fromPackageName('composer', 'vendor/package'), $version),
            status: Status::FalsePositive,
            reason: 'The advisory names the wrong range for this release.',
            origin: Origin::user('42'),
            issuedAt: new \DateTimeImmutable(AssessmentBuilder::ISSUED_AT),
        );
    }

    /**
     * @param list<string> $identities
     */
    private function assessment(
        Status $status = Status::FalsePositive,
        string $reason = 'The advisory names the wrong range for this release.',
        array $identities = ['composer|vendor/package|cve|CVE-2026-1234'],
        ?Justification $justification = null,
        ?Response $response = null,
        ?Severity $acceptedSeverity = null,
        ?\DateTimeImmutable $expiresAt = null,
    ): Assessment {
        return new Assessment(
            identities: $identities,
            component: PackageRef::fromString('pkg:composer/vendor/package@1.4.2'),
            status: $status,
            reason: $reason,
            origin: Origin::user('42'),
            issuedAt: new \DateTimeImmutable(AssessmentBuilder::ISSUED_AT),
            justification: $justification,
            response: $response,
            acceptedSeverity: $acceptedSeverity,
            expiresAt: $expiresAt,
        );
    }
}
