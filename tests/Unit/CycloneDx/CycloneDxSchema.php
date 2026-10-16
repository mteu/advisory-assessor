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

use JsonSchema\Constraints\Factory;
use JsonSchema\SchemaStorage;
use JsonSchema\Validator;

/**
 * Validates against the official CycloneDX 1.6 schema, vendored under
 * tests/Fixtures/CycloneDx. The schemas reference each other by their
 * cyclonedx.org ids, so all three are registered up front and nothing is
 * fetched.
 */
final class CycloneDxSchema
{
    private const string SCHEMA_BASE_URI = 'http://cyclonedx.org/schema/';

    private const string BOM_SCHEMA = 'bom-1.6.schema.json';

    private const array REFERENCED_SCHEMAS = ['spdx.schema.json', 'jsf-0.82.schema.json'];

    /**
     * @return list<string> one line per violation; empty when the document is valid
     */
    public static function findViolations(string $json): array
    {
        $storage = new SchemaStorage();
        foreach ([self::BOM_SCHEMA, ...self::REFERENCED_SCHEMAS] as $file) {
            $storage->addSchema(self::SCHEMA_BASE_URI . $file, self::decodeSchema($file));
        }

        $document = json_decode($json, flags: JSON_THROW_ON_ERROR);
        $validator = new Validator(new Factory($storage));
        $validator->validate($document, $storage->getSchema(self::SCHEMA_BASE_URI . self::BOM_SCHEMA));

        $violations = [];
        foreach ($validator->getErrors() as $error) {
            $violations[] = is_array($error)
                ? sprintf('%s: %s', self::describe($error, 'property'), self::describe($error, 'message'))
                : 'unreadable violation';
        }

        return $violations;
    }

    private static function decodeSchema(string $file): object
    {
        $schema = json_decode(
            (string)file_get_contents(dirname(__DIR__, 2) . '/Fixtures/CycloneDx/' . $file),
            flags: JSON_THROW_ON_ERROR,
        );

        if (!is_object($schema)) {
            throw new \UnexpectedValueException(sprintf('%s is not a JSON schema.', $file));
        }

        return $schema;
    }

    /**
     * @param array<array-key, mixed> $error justinrainbow/json-schema reports errors as untyped arrays
     */
    private static function describe(array $error, string $key): string
    {
        $value = $error[$key] ?? '';

        return is_scalar($value) ? (string)$value : '';
    }
}
