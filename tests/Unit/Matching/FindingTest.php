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

use mteu\AdvisoryAssessor\Matching\Finding;
use mteu\AdvisoryAssessor\Tests\Unit\Advisory\AdvisoryBuilder;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Package\PackageUrl;
use mteu\AdvisoryMatcher\Source\PackageRef;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;

#[CoversClass(Finding::class)]
final class FindingTest extends TestCase
{
    /**
     * @return iterable<string, array{Ecosystem, string, string}>
     */
    public static function advisoriesAndComponentsOfOnePackage(): iterable
    {
        yield 'a Composer package' => [Ecosystem::Composer, 'symfony/http-kernel', 'pkg:composer/symfony/http-kernel@5.4.19'];
        yield 'a Composer package spelled in mixed case' => [Ecosystem::Composer, 'symfony/http-kernel', 'pkg:composer/Symfony/HTTP-Kernel@5.4.19'];
        yield 'a scoped npm package' => [Ecosystem::Npm, '@acme/widgets', 'pkg:npm/%40acme/widgets@2.1.0'];
        yield 'an npm package published in mixed case' => [Ecosystem::Npm, 'JSONStream', 'pkg:npm/JSONStream@1.3.5'];
        yield 'the PHP runtime' => [Ecosystem::Php, 'php', 'pkg:generic/php@8.3.6'];
    }

    #[Test]
    #[DataProvider('advisoriesAndComponentsOfOnePackage')]
    public function pairsAnAdvisoryWithAComponentOfThePackageItIsFiledUnder(Ecosystem $ecosystem, string $packageName, string $purl): void
    {
        $component = PackageRef::fromString($purl);

        self::assertSame($component, (new Finding(AdvisoryBuilder::build(packageName: $packageName, ecosystem: $ecosystem), $component))->component);
    }

    /**
     * @return iterable<string, array{Ecosystem, string, string}>
     */
    public static function advisoriesAndComponentsOfDifferentPackages(): iterable
    {
        yield 'another Composer package' => [Ecosystem::Composer, 'symfony/http-kernel', 'pkg:composer/symfony/console@5.4.19'];
        yield 'one name in another ecosystem' => [Ecosystem::Npm, 'lodash', 'pkg:composer/lodash/lodash@4.17.20'];
        yield 'an npm package differing in case only' => [Ecosystem::Npm, 'JSONStream', 'pkg:npm/jsonstream@1.3.5'];
    }

    #[Test]
    #[DataProvider('advisoriesAndComponentsOfDifferentPackages')]
    public function refusesAnAdvisoryAndAComponentOfDifferentPackages(Ecosystem $ecosystem, string $packageName, string $purl): void
    {
        $advisory = AdvisoryBuilder::build(packageName: $packageName, ecosystem: $ecosystem);

        $this->expectException(\InvalidArgumentException::class);

        new Finding($advisory, PackageRef::fromString($purl));
    }

    #[Test]
    #[TestWith([''])]
    #[TestWith(['   '])]
    public function refusesAComponentWithoutAVersion(string $version): void
    {
        $advisory = AdvisoryBuilder::build(packageName: 'vendor/package');

        $this->expectException(\InvalidArgumentException::class);

        new Finding($advisory, new PackageRef(PackageUrl::fromPackageName('composer', 'vendor/package'), $version));
    }
}
