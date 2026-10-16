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
use mteu\AdvisoryAssessor\Document\AuthorKind;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;

#[CoversClass(Author::class)]
final class AuthorTest extends TestCase
{
    #[Test]
    public function aPersonAuthorNamesThePerson(): void
    {
        $author = Author::person('Jane Doe');

        self::assertSame(AuthorKind::Person, $author->kind);
        self::assertSame('Jane Doe', $author->name);
    }

    #[Test]
    public function anOrganizationAuthorNamesTheOrganization(): void
    {
        $author = Author::organization('Acme Security Team');

        self::assertSame(AuthorKind::Organization, $author->kind);
        self::assertSame('Acme Security Team', $author->name);
    }

    #[Test]
    #[TestWith([''])]
    #[TestWith([' '])]
    public function anAuthorHasToNameSomebody(string $name): void
    {
        $this->expectException(\InvalidArgumentException::class);

        Author::organization($name);
    }
}
