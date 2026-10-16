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

use mteu\AdvisoryMatcher\Source\PackageRef;
use mteu\AdvisoryAssessor\Assessment\Justification;
use mteu\AdvisoryAssessor\Assessment\Origin;
use mteu\AdvisoryAssessor\Assessment\Response;
use mteu\AdvisoryAssessor\Assessment\Assessment;
use mteu\AdvisoryAssessor\Assessment\Status;
use mteu\AdvisoryMatcher\Advisory\Advisory;
use mteu\AdvisoryMatcher\Advisory\AdvisoryFingerprint;
use mteu\AdvisoryMatcher\Advisory\Severity;

final class AssessmentBuilder
{
    public const string ISSUED_AT = '2026-10-01T00:00:00+00:00';

    public static function notAffected(Advisory $advisory, string $purl, string $expiresAt = ''): Assessment
    {
        return self::build($advisory, $purl, Status::NotAffected, expiresAt: $expiresAt, justification: Justification::CodeNotReachable);
    }

    public static function falsePositive(Advisory $advisory, string $purl): Assessment
    {
        return self::build($advisory, $purl, Status::FalsePositive);
    }

    public static function affected(Advisory $advisory, string $purl, string $expiresAt = ''): Assessment
    {
        return self::build(
            $advisory,
            $purl,
            Status::Affected,
            expiresAt: $expiresAt,
            response: Response::WillNotFix,
            acceptedSeverity: $advisory->severity,
        );
    }

    public static function fixed(Advisory $advisory, string $purl): Assessment
    {
        return self::build($advisory, $purl, Status::Fixed);
    }

    public static function underInvestigation(Advisory $advisory, string $purl): Assessment
    {
        return self::build($advisory, $purl, Status::UnderInvestigation, reason: '');
    }

    private static function build(
        Advisory $advisory,
        string $purl,
        Status $status,
        string $reason = 'Assessed by the team.',
        string $expiresAt = '',
        ?Justification $justification = null,
        ?Response $response = null,
        ?Severity $acceptedSeverity = null,
    ): Assessment {
        return new Assessment(
            identities: AdvisoryFingerprint::identitiesOf($advisory),
            component: PackageRef::fromString($purl),
            status: $status,
            reason: $reason,
            origin: Origin::user('42'),
            issuedAt: new \DateTimeImmutable(self::ISSUED_AT),
            justification: $justification,
            response: $response,
            acceptedSeverity: $acceptedSeverity,
            expiresAt: $expiresAt === '' ? null : new \DateTimeImmutable($expiresAt),
        );
    }
}
