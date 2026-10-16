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

/**
 * The advisory is known only by an id no other tool can read, so writing it
 * would publish something nobody can match. Check
 * {@see CycloneDxVexWriter::canWrite()} up front.
 */
final class UnexportableAssessments extends \Exception
{
    /**
     * @param list<Assessment> $assessments
     */
    public function __construct(
        public readonly array $assessments,
    ) {
        parent::__construct(sprintf(
            '%d assessment(s) name their advisory by no id other tools can read.',
            count($assessments),
        ));
    }
}
