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

use mteu\AdvisoryAssessor\CycloneDx\ExportScope;
use mteu\AdvisoryAssessor\Assessment\Status;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(ExportScope::class)]
final class ExportScopeTest extends TestCase
{
    /**
     * @return iterable<string, array{ExportScope, Status, bool}>
     */
    public static function scopesAndStatuses(): iterable
    {
        yield 'resolved only keeps not_affected' => [ExportScope::ResolvedOnly, Status::NotAffected, true];
        yield 'resolved only keeps false_positive' => [ExportScope::ResolvedOnly, Status::FalsePositive, true];
        yield 'resolved only keeps fixed' => [ExportScope::ResolvedOnly, Status::Fixed, true];
        yield 'resolved only drops affected' => [ExportScope::ResolvedOnly, Status::Affected, false];
        yield 'resolved only drops under_investigation' => [ExportScope::ResolvedOnly, Status::UnderInvestigation, false];

        foreach (Status::cases() as $status) {
            yield 'all keeps ' . $status->value => [ExportScope::All, $status, true];
        }
    }

    #[Test]
    #[DataProvider('scopesAndStatuses')]
    public function includesOnlyWhatTheScopeAllows(ExportScope $scope, Status $status, bool $expected): void
    {
        self::assertSame($expected, $scope->includes($status));
    }
}
