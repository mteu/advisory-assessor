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
 * Two or more assessments cover the same advisory on the same component. A
 * reader of the document couldn't tell which one counts, so the caller has to
 * decide first, e.g. with
 * {@see \mteu\AdvisoryAssessor\Matching\AssessmentMatcher::resolve()}.
 */
final class ContradictingAssessments extends \Exception
{
    /**
     * @param list<Assessment> $assessments every assessment that shares an advisory and a component with another, in the order given
     */
    public function __construct(
        public readonly array $assessments,
    ) {
        parent::__construct(sprintf(
            '%d assessment(s) speak about an advisory on a component that another assessment speaks about too. Resolve them before writing.',
            count($assessments),
        ));
    }
}
