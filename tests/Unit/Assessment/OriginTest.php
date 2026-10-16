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

namespace mteu\AdvisoryAssessor\Tests\Unit\Assessment;

use mteu\AdvisoryAssessor\Assessment\Origin;
use mteu\AdvisoryAssessor\Assessment\OriginKind;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;

#[CoversClass(Origin::class)]
final class OriginTest extends TestCase
{
    #[Test]
    public function aUserOriginNamesTheUserAndNoCommit(): void
    {
        $origin = Origin::user('42');

        self::assertSame(OriginKind::User, $origin->kind);
        self::assertSame('42', $origin->actor);
        self::assertSame('', $origin->commit);
    }

    #[Test]
    public function aPipelineOriginNamesThePipelineAndTheCommit(): void
    {
        $origin = Origin::pipeline('gitlab-ci', '9396dcba47388945ead289e5574ae1c862b26073');

        self::assertSame(OriginKind::Pipeline, $origin->kind);
        self::assertSame('gitlab-ci', $origin->actor);
        self::assertSame('9396dcba47388945ead289e5574ae1c862b26073', $origin->commit);
    }

    #[Test]
    public function anOriginHasToNameSomebody(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        Origin::user(' ');
    }

    #[Test]
    #[TestWith([''])]
    #[TestWith(['main'])]
    #[TestWith(['9396dc'])]
    #[TestWith(['9396dcb; rm -rf /'])]
    public function aPipelineOriginRejectsAnythingButACommitHash(string $commit): void
    {
        $this->expectException(\InvalidArgumentException::class);

        Origin::pipeline('gitlab-ci', $commit);
    }
}
