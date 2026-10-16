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

namespace mteu\AdvisoryAssessor\Matching;

use mteu\AdvisoryAssessor\Assessment\Assessment;

final readonly class Resolution
{
    /**
     * @param list<Assessment> $covering every assessment that covers the finding, most alarming first; the first one decides
     */
    public function __construct(
        public Finding $finding,
        public array $covering,
    ) {
        if (!array_is_list($covering)) {
            throw new \InvalidArgumentException('The covering assessments have to be a list.');
        }

        $previousRank = PHP_INT_MAX;
        foreach ($covering as $assessment) {
            if (!$assessment instanceof Assessment) {
                throw new \InvalidArgumentException('A covering assessment has to be an Assessment.');
            }

            if ($assessment->status->getAlarmRank() > $previousRank) {
                throw new \InvalidArgumentException('The covering assessments have to be ordered most alarming first.');
            }

            $previousRank = $assessment->status->getAlarmRank();
        }
    }

    public function hasAssessment(): bool
    {
        return $this->covering !== [];
    }

    public function isHidden(): bool
    {
        return $this->covering !== [] && $this->covering[0]->status->hidesFinding();
    }
}
