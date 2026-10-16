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

use mteu\AdvisoryAssessor\Assessment\Assessment;

final readonly class VexReading
{
    /**
     * @param list<Assessment> $assessments
     * @param list<int> $skippedEntries indices in `vulnerabilities` of the entries that claim nothing: no analysis, or an analysis without a state
     */
    public function __construct(
        public array $assessments,
        public array $skippedEntries,
    ) {
    }
}
