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
 * {@see CycloneDxVexReader} found entries it can't use. All of them are listed,
 * so the author can fix them in one pass.
 */
final class RejectedVexEntries extends \Exception
{
    /**
     * @param list<RejectedVexEntry> $entries ordered by index, then by ref
     */
    public function __construct(
        public readonly array $entries,
    ) {
        $indices = array_values(array_unique(array_map(
            static fn (RejectedVexEntry $entry): int => $entry->index,
            $entries,
        )));

        // Only indices: the ids and refs come from the document, and an
        // exception message ends up in logs and backend views.
        parent::__construct(sprintf(
            'The VEX document holds entries that cannot be read, at index %s.',
            implode(', ', $indices),
        ));
    }
}
