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

namespace mteu\AdvisoryAssessor\Tests\Unit\CycloneDx;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The writer's tests lean on the schema check. These make sure it can fail.
 */
#[CoversNothing]
final class CycloneDxSchemaTest extends TestCase
{
    #[Test]
    public function rejectsAnAnalysisStateTheSpecificationDoesNotKnow(): void
    {
        self::assertNotSame([], CycloneDxSchema::findViolations($this->documentWithState('resolved_with_hope')));
    }

    #[Test]
    public function rejectsAMalformedTimestamp(): void
    {
        $json = str_replace('2026-10-08T12:30:00Z', 'yesterday', $this->documentWithState('in_triage'));

        self::assertNotSame([], CycloneDxSchema::findViolations($json));
    }

    #[Test]
    public function acceptsAMinimalVexDocument(): void
    {
        self::assertSame([], CycloneDxSchema::findViolations($this->documentWithState('in_triage')));
    }

    private function documentWithState(string $state): string
    {
        return json_encode(
            [
                'bomFormat' => 'CycloneDX',
                'specVersion' => '1.6',
                'version' => 1,
                'metadata' => ['timestamp' => '2026-10-08T12:30:00Z'],
                'vulnerabilities' => [
                    ['id' => 'CVE-2026-1234', 'analysis' => ['state' => $state]],
                ],
            ],
            JSON_THROW_ON_ERROR,
        );
    }
}
