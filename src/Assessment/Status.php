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

namespace mteu\AdvisoryAssessor\Assessment;

enum Status: string
{
    case NotAffected = 'not_affected';
    case FalsePositive = 'false_positive';
    case Affected = 'affected';
    case Fixed = 'fixed';
    case UnderInvestigation = 'under_investigation';

    /**
     * The higher rank wins when several assessments cover one finding. The one
     * that hides less beats the one that hides more.
     */
    public function getAlarmRank(): int
    {
        return match ($this) {
            self::FalsePositive => 1,
            self::NotAffected => 2,
            self::Fixed => 3,
            self::Affected => 4,
            self::UnderInvestigation => 5,
        };
    }

    public function hidesFinding(): bool
    {
        return $this !== self::UnderInvestigation;
    }
}
