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

namespace mteu\AdvisoryAssessor\Document;

/**
 * Who publishes a VEX document: a person or an organization. CycloneDX writes
 * them to different fields.
 */
final readonly class Author
{
    private function __construct(
        public AuthorKind $kind,
        public string $name,
    ) {
        if (trim($name) === '') {
            throw new \InvalidArgumentException('A VEX document has to name its author.');
        }
    }

    public static function person(string $name): self
    {
        return new self(AuthorKind::Person, $name);
    }

    public static function organization(string $name): self
    {
        return new self(AuthorKind::Organization, $name);
    }
}
