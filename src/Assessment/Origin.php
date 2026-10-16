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

final readonly class Origin
{
    private function __construct(
        public OriginKind $kind,
        public string $actor,
        public string $commit,
    ) {
        if (trim($actor) === '') {
            throw new \InvalidArgumentException('An assessment has to name who made it.');
        }

        if ($kind === OriginKind::User && $commit !== '') {
            throw new \InvalidArgumentException('An assessment made by a user names no commit.');
        }

        // A pipeline assessment hides findings without a person looking, so it
        // has to point at the exact revision that carried it.
        if ($kind === OriginKind::Pipeline && preg_match('/^[0-9a-f]{7,64}$/i', $commit) !== 1) {
            throw new \InvalidArgumentException('An assessment imported by a pipeline has to name the commit it came from.');
        }
    }

    public static function user(string $userId): self
    {
        return new self(OriginKind::User, $userId, '');
    }

    public static function pipeline(string $pipeline, string $commit): self
    {
        return new self(OriginKind::Pipeline, $pipeline, $commit);
    }
}
