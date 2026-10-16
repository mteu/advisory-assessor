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

/**
 * CycloneDX's justification vocabulary, which is finer than CSAF's, plus
 * `component_not_present`, which CycloneDX lacks. Writers map it down.
 */
enum Justification: string
{
    case CodeNotPresent = 'code_not_present';
    case CodeNotReachable = 'code_not_reachable';
    case RequiresConfiguration = 'requires_configuration';
    case RequiresDependency = 'requires_dependency';
    case RequiresEnvironment = 'requires_environment';
    case ProtectedByCompiler = 'protected_by_compiler';
    case ProtectedAtRuntime = 'protected_at_runtime';
    case ProtectedAtPerimeter = 'protected_at_perimeter';
    case ProtectedByMitigatingControl = 'protected_by_mitigating_control';
    case ComponentNotPresent = 'component_not_present';
}
