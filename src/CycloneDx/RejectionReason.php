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

/**
 * Why {@see CycloneDxVexReader} could not use an entry of a VEX document.
 */
enum RejectionReason: string
{
    case MissingVulnerabilityId = 'missing_vulnerability_id';
    case MissingJustification = 'missing_justification';
    case UnknownJustification = 'unknown_justification';
    case MissingResponse = 'missing_response';
    case MissingAcceptedSeverity = 'missing_accepted_severity';
    case UnknownAcceptedSeverity = 'unknown_accepted_severity';
    case MissingReason = 'missing_reason';
    case MissingIssueTime = 'missing_issue_time';
    case IssuedInTheFuture = 'issued_in_the_future';
    case NoAffectedComponent = 'no_affected_component';
    case ComponentInAnotherDocument = 'component_in_another_document';
    case UnknownComponent = 'unknown_component';
    case AmbiguousComponent = 'ambiguous_component';
    case VersionRange = 'version_range';
    case ComponentWithoutPackageUrl = 'component_without_package_url';
    case InvalidPackageUrl = 'invalid_package_url';
    case UnsupportedEcosystem = 'unsupported_ecosystem';
    case Duplicate = 'duplicate';
}
