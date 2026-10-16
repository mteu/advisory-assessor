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

use mteu\AdvisoryMatcher\Advisory\Severity;
use mteu\AdvisoryMatcher\Source\PackageRef;

/**
 * One human or pipeline claim about one advisory on one component at one
 * version. Whether it still covers a finding is decided by
 * {@see \mteu\AdvisoryAssessor\Matching\AssessmentMatcher}, never here.
 */
final readonly class Assessment
{
    /**
     * @param list<string> $identities AdvisoryFingerprint::identitiesOf() of the advisory when the assessment was made
     * @param PackageRef $component the component at the one version the assessment was made for
     * @param string $reason exported as the impact statement or the action statement; may be empty only while under investigation
     * @param Justification|null $justification required for not_affected, forbidden otherwise
     * @param Response|null $response required for affected, forbidden otherwise
     * @param Severity|null $acceptedSeverity required for affected, forbidden otherwise
     * @param \DateTimeImmutable|null $expiresAt null for never; internal, neither VEX format carries it
     */
    public function __construct(
        public array $identities,
        public PackageRef $component,
        public Status $status,
        public string $reason,
        public Origin $origin,
        public \DateTimeImmutable $issuedAt,
        public ?Justification $justification = null,
        public ?Response $response = null,
        public ?Severity $acceptedSeverity = null,
        public ?\DateTimeImmutable $expiresAt = null,
    ) {
        self::rejectUnusableIdentities($identities);

        if (trim($component->version) === '') {
            throw new \InvalidArgumentException('An assessment names a component at one exact version.');
        }

        if (($status === Status::NotAffected) !== ($justification !== null)) {
            throw new \InvalidArgumentException('An assessment carries a justification if and only if it says not_affected.');
        }

        if (($status === Status::Affected) !== ($response !== null)) {
            throw new \InvalidArgumentException('An assessment carries a response if and only if it says affected.');
        }

        if (($status === Status::Affected) !== ($acceptedSeverity !== null)) {
            throw new \InvalidArgumentException('An assessment records an accepted severity if and only if it says affected.');
        }

        if ($status !== Status::UnderInvestigation && trim($reason) === '') {
            throw new \InvalidArgumentException('An assessment has to give a reason unless it is under investigation.');
        }

        if ($expiresAt !== null && $expiresAt <= $issuedAt) {
            throw new \InvalidArgumentException('An assessment has to expire after it was issued.');
        }
    }

    public function isExpiredAt(\DateTimeImmutable $now): bool
    {
        return $this->expiresAt !== null && $this->expiresAt <= $now;
    }

    /**
     * @param array<array-key, mixed> $identities checked here, so no shape can be assumed yet
     */
    private static function rejectUnusableIdentities(array $identities): void
    {
        if ($identities === [] || !array_is_list($identities)) {
            throw new \InvalidArgumentException('An assessment has to name the advisory by a non-empty list of identities.');
        }

        foreach ($identities as $identity) {
            if (!is_string($identity) || trim($identity) === '') {
                throw new \InvalidArgumentException('An advisory identity has to be a non-empty string.');
            }
        }
    }
}
