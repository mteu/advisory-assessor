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
 * One reason one entry of a VEX document was rejected. The id and the ref are
 * copied from the document, so escape them before you show them.
 */
final readonly class RejectedVexEntry
{
    /**
     * @param int $index the entry's position in `vulnerabilities`, counted from 0
     * @param string $vulnerabilityId the entry's `id` as written; '' when it has none
     * @param string $ref the `affects` ref the reason is about; '' when it is about the whole entry
     */
    public function __construct(
        public int $index,
        public string $vulnerabilityId,
        public string $ref,
        public RejectionReason $reason,
    ) {
        if ($index < 0) {
            throw new \InvalidArgumentException('An entry index counts from 0.');
        }
    }
}
