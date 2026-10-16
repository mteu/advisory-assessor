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

namespace mteu\AdvisoryAssessor\Assessment;

enum Response: string
{
    case WillNotFix = 'will_not_fix';
    case CanNotFix = 'can_not_fix';
    case WorkaroundAvailable = 'workaround_available';
    case Update = 'update';
    // A CSAF writer maps it to `vendor_fix`: a rollback ships a release that
    // is not affected.
    case Rollback = 'rollback';
}
