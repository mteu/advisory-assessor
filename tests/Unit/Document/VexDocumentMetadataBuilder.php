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

namespace mteu\AdvisoryAssessor\Tests\Unit\Document;

use mteu\AdvisoryAssessor\Document\Author;
use mteu\AdvisoryAssessor\Document\VexDocumentMetadata;

final class VexDocumentMetadataBuilder
{
    public const string DOCUMENT_ID = '3e671687-395b-41f5-a30f-a58921a69b79';

    public const string AUTHOR = 'Acme Security Team';

    public const string ISSUED_AT = '2026-10-08T12:30:00+00:00';

    public static function build(string $issuedAt = self::ISSUED_AT, int $version = 1): VexDocumentMetadata
    {
        return new VexDocumentMetadata(
            documentId: self::DOCUMENT_ID,
            version: $version,
            author: Author::organization(self::AUTHOR),
            issuedAt: new \DateTimeImmutable($issuedAt),
        );
    }
}
