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

use mteu\AdvisoryAssessor\Assessment\Status;

/**
 * Which assessments a VEX document may carry. `affected` and
 * `under_investigation` list known, unfixed vulnerabilities in a production
 * system, so the caller must choose to include them. There is no default.
 */
enum ExportScope: string
{
    case ResolvedOnly = 'resolved_only';
    case All = 'all';

    public function includes(Status $status): bool
    {
        return match ($this) {
            self::All => true,
            self::ResolvedOnly => match ($status) {
                Status::NotAffected, Status::FalsePositive, Status::Fixed => true,
                Status::Affected, Status::UnderInvestigation => false,
            },
        };
    }
}
