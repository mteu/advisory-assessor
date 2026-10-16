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
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;

#[CoversClass(VexDocumentMetadata::class)]
final class VexDocumentMetadataTest extends TestCase
{
    #[Test]
    #[TestWith([VexDocumentMetadataBuilder::DOCUMENT_ID])]
    #[TestWith(['3E671687-395B-41F5-A30F-A58921A69B79'])]
    public function acceptsAUuidInEitherCase(string $documentId): void
    {
        $metadata = $this->metadata($documentId, 1);

        self::assertSame($documentId, $metadata->documentId);
    }

    #[Test]
    #[TestWith([''])]
    #[TestWith(['acme-vex-2026'])]
    #[TestWith(['urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79'])]
    #[TestWith(['3e671687-395b-41f5-a30f-a58921a69b79 '])]
    #[TestWith(["3e671687-395b-41f5-a30f-a58921a69b79\n"])]
    public function rejectsADocumentIdThatIsNotAUuid(string $documentId): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->metadata($documentId, 1);
    }

    #[Test]
    #[TestWith([0])]
    #[TestWith([-1])]
    public function rejectsAVersionBelowOne(int $version): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->metadata(VexDocumentMetadataBuilder::DOCUMENT_ID, $version);
    }

    private function metadata(string $documentId, int $version): VexDocumentMetadata
    {
        return new VexDocumentMetadata(
            documentId: $documentId,
            version: $version,
            author: Author::organization(VexDocumentMetadataBuilder::AUTHOR),
            issuedAt: new \DateTimeImmutable(VexDocumentMetadataBuilder::ISSUED_AT),
        );
    }
}
