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

use mteu\AdvisoryAssessor\Assessment\Origin;
use mteu\AdvisoryAssessor\CycloneDx\CycloneDxVexReader;
use mteu\AdvisoryAssessor\Tests\Unit\Advisory\AdvisoryBuilder;
use mteu\AdvisoryAssessor\Tests\Unit\Clock\FrozenClock;
use mteu\AdvisoryMatcher\Advisory\AdvisoryFingerprint;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\SbomParser\Parser\CycloneDxParser;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * A statement read from a VEX document has to name an advisory exactly the
 * way `AdvisoryFingerprint::identitiesOf()` does, or it never covers the
 * finding. The two are built by different code paths of the matcher.
 */
#[CoversClass(CycloneDxVexReader::class)]
final class MatcherIdentityContractTest extends TestCase
{
    private const string NOW = '2026-10-08T12:30:00+00:00';

    private const string CVE = 'CVE-2026-1234';

    private const string GHSA = 'GHSA-ABCD-EFGH-IJKL';

    private const string NATIVE_ID = 'PKSA-1111-2222-3333';

    /**
     * @return iterable<string, array{Ecosystem, string, string}>
     */
    public static function packagesAsTheFeedsAndAsAVexDocumentNameThem(): iterable
    {
        yield 'Composer package' => [Ecosystem::Composer, 'symfony/http-kernel', 'pkg:composer/symfony/http-kernel@5.4.19'];
        yield 'Composer package in mixed case' => [Ecosystem::Composer, 'symfony/http-kernel', 'pkg:composer/Symfony/HTTP-Kernel@5.4.19'];
        yield 'npm package' => [Ecosystem::Npm, 'lodash', 'pkg:npm/lodash@4.17.20'];
        yield 'scoped npm package' => [Ecosystem::Npm, '@acme/widgets', 'pkg:npm/@acme/widgets@2.1.0'];
        yield 'scoped npm package with an encoded scope' => [Ecosystem::Npm, '@acme/widgets', 'pkg:npm/%40acme/widgets@2.1.0'];
        yield 'npm package published in mixed case' => [Ecosystem::Npm, 'JSONStream', 'pkg:npm/JSONStream@1.3.5'];
        yield 'PHP runtime' => [Ecosystem::Php, 'php', 'pkg:generic/php@8.3.6'];
    }

    #[Test]
    #[DataProvider('packagesAsTheFeedsAndAsAVexDocumentNameThem')]
    public function readsEveryIdentityTheMatcherFilesTheAdvisoryUnder(Ecosystem $ecosystem, string $packageName, string $purl): void
    {
        $advisory = AdvisoryBuilder::build(
            advisoryId: self::NATIVE_ID,
            packageName: $packageName,
            ecosystem: $ecosystem,
            remoteId: self::GHSA,
            cve: self::CVE,
        );

        $assessments = $this->reader()->read(self::documentNamingTheAdvisoryOn($purl), Origin::pipeline('acme/shop', 'a1b2c3d4'), null)->assessments;

        self::assertCount(1, $assessments);
        self::assertEqualsCanonicalizing(AdvisoryFingerprint::identitiesOf($advisory), $assessments[0]->identities);
    }

    private function reader(): CycloneDxVexReader
    {
        return new CycloneDxVexReader(new CycloneDxParser(), FrozenClock::at(self::NOW));
    }

    private static function documentNamingTheAdvisoryOn(string $purl): string
    {
        return json_encode([
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.6',
            'version' => 1,
            'components' => [['type' => 'library', 'bom-ref' => $purl, 'name' => 'package', 'purl' => $purl]],
            'vulnerabilities' => [[
                'id' => self::CVE,
                'references' => [
                    ['id' => self::GHSA, 'source' => ['name' => 'GitHub']],
                    ['id' => self::NATIVE_ID, 'source' => ['name' => 'Packagist']],
                ],
                'analysis' => [
                    'state' => 'not_affected',
                    'justification' => 'code_not_reachable',
                    'detail' => 'Never called.',
                    'firstIssued' => '2026-10-01T00:00:00Z',
                ],
                'affects' => [['ref' => $purl]],
            ]],
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }
}
