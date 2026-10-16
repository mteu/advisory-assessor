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

/**
 * @internal
 */
enum IdentityKind: string
{
    case Cve = 'cve';
    case Ghsa = 'ghsa';
    case Native = 'id';
    case Hash = 'hash';

    /**
     * Lower comes first. A CVE is what most tools match on, a GHSA next, the
     * feed's own id last.
     */
    public function getPreferenceRank(): int
    {
        return match ($this) {
            self::Cve => 0,
            self::Ghsa => 1,
            self::Native => 2,
            self::Hash => 3,
        };
    }

    /**
     * A hash identity is derived from the advisory's title and range. It means
     * nothing outside this suite.
     */
    public function isReadableByOtherTools(): bool
    {
        return $this !== self::Hash;
    }
}
