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

use mteu\AdvisoryMatcher\Advisory\Advisory;
use mteu\AdvisoryMatcher\Source\PackageRef;

final readonly class Finding
{
    /**
     * @param PackageRef $component the component as deployed now, at its current version
     */
    public function __construct(
        public Advisory $advisory,
        public PackageRef $component,
    ) {
        if (trim($component->version) === '') {
            throw new \InvalidArgumentException('A finding names a component at one exact version.');
        }

        if (!$advisory->package->equals($component->package)) {
            throw new \InvalidArgumentException('A finding pairs an advisory with a component of the package it is filed under.');
        }
    }
}
