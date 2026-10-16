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

use mteu\AdvisoryAssessor\Assessment\Status;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(Status::class)]
final class StatusTest extends TestCase
{
    #[Test]
    public function ranksTheStatusesInTheOrderTheAdrFixes(): void
    {
        $statuses = Status::cases();
        usort($statuses, static fn (Status $left, Status $right): int => $right->getAlarmRank() <=> $left->getAlarmRank());

        self::assertSame(
            [Status::UnderInvestigation, Status::Affected, Status::Fixed, Status::NotAffected, Status::FalsePositive],
            $statuses,
        );
    }

    #[Test]
    public function onlyUnderInvestigationLeavesTheFindingVisible(): void
    {
        $visible = array_values(array_filter(
            Status::cases(),
            static fn (Status $status): bool => !$status->hidesFinding(),
        ));

        self::assertSame([Status::UnderInvestigation], $visible);
    }
}
