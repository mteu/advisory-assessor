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
 * Document-level fields from CISA's minimum requirements. The caller stores
 * them between exports: the id stays for the life of the VEX, the version and
 * issue time change with its content. Same metadata and assessments give the
 * same bytes.
 */
final readonly class VexDocumentMetadata
{
    private const string UUID_PATTERN = '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iD';

    /**
     * @param string $documentId a UUID, the same for every version of one document
     * @param int $version starts at 1 and rises whenever the content changes
     * @param \DateTimeImmutable $issuedAt when this version was issued; no earlier than the newest assessment it carries
     */
    public function __construct(
        public string $documentId,
        public int $version,
        public Author $author,
        public \DateTimeImmutable $issuedAt,
    ) {
        if (preg_match(self::UUID_PATTERN, $documentId) !== 1) {
            throw new \InvalidArgumentException('A VEX document has to be identified by a UUID.');
        }

        if ($version < 1) {
            throw new \InvalidArgumentException('A VEX document version starts at 1.');
        }
    }
}
