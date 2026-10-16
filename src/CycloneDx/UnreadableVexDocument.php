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

namespace mteu\AdvisoryAssessor\CycloneDx;

use mteu\SbomParser\Exception\SbomParseException;

/**
 * The document is not CycloneDX 1.4 to 1.7 JSON. No entry was looked at.
 *
 * The parser's exception is the previous one. Its message may quote the
 * document: log it, but don't show it to whoever uploaded the file.
 */
final class UnreadableVexDocument extends \Exception
{
    public static function becauseParsingFailed(SbomParseException $previous): self
    {
        return new self('Not a CycloneDX 1.4 to 1.7 JSON document.', 0, $previous);
    }
}
