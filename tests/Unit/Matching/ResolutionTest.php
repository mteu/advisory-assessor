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

namespace mteu\AdvisoryAssessor\Tests\Unit\Matching;

use mteu\AdvisoryMatcher\Source\PackageRef;
use mteu\AdvisoryAssessor\Matching\Finding;
use mteu\AdvisoryAssessor\Matching\Resolution;
use mteu\AdvisoryAssessor\Tests\Unit\Advisory\AdvisoryBuilder;
use mteu\AdvisoryAssessor\Tests\Unit\Assessment\AssessmentBuilder;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(Resolution::class)]
final class ResolutionTest extends TestCase
{
    #[Test]
    public function rejectsAssessmentsThatAreNotOrderedMostAlarmingFirst(): void
    {
        $advisory = AdvisoryBuilder::build();
        $purl = 'pkg:composer/vendor/package@1.4.2';

        $this->expectException(\InvalidArgumentException::class);

        new Resolution(
            new Finding($advisory, PackageRef::fromString($purl)),
            [AssessmentBuilder::notAffected($advisory, $purl), AssessmentBuilder::underInvestigation($advisory, $purl)],
        );
    }
}
