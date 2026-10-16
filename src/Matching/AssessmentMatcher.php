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

namespace mteu\AdvisoryAssessor\Matching;

use mteu\AdvisoryAssessor\Assessment\Assessment;
use mteu\AdvisoryAssessor\Assessment\Status;
use mteu\AdvisoryMatcher\Advisory\AdvisoryFingerprint;
use Psr\Clock\ClockInterface;

/**
 * Decides whether an assessment still covers a finding. Consumers should ask
 * here instead of reimplementing the rule.
 *
 * Every condition keeps an assessment from outliving what it was made about.
 * A finding that loses all its assessments simply shows up again.
 */
final readonly class AssessmentMatcher
{
    public function __construct(
        private ClockInterface $clock,
    ) {
    }

    public function covers(Assessment $assessment, Finding $finding): bool
    {
        return $this->coversAt($assessment, $finding, AdvisoryFingerprint::identitiesOf($finding->advisory), $this->clock->now());
    }

    /**
     * @param list<Assessment> $assessments
     */
    public function resolve(Finding $finding, array $assessments): Resolution
    {
        $now = $this->clock->now();
        $findingIdentities = AdvisoryFingerprint::identitiesOf($finding->advisory);

        $covering = array_values(array_filter(
            $assessments,
            fn (Assessment $assessment): bool => $this->coversAt($assessment, $finding, $findingIdentities, $now),
        ));

        usort(
            $covering,
            static fn (Assessment $left, Assessment $right): int => $right->status->getAlarmRank() <=> $left->status->getAlarmRank(),
        );

        return new Resolution($finding, $covering);
    }

    /**
     * @param list<string> $findingIdentities
     */
    private function coversAt(Assessment $assessment, Finding $finding, array $findingIdentities, \DateTimeImmutable $now): bool
    {
        if ($assessment->isExpiredAt($now)) {
            return false;
        }

        // The version changed.
        if (!$assessment->component->equals($finding->component)) {
            return false;
        }

        if ($this->exceedsAcceptedSeverity($assessment, $finding)) {
            return false;
        }

        // By identity rather than by canonical key, which moves when a feed
        // backfills a CVE.
        return array_intersect($assessment->identities, $findingIdentities) !== [];
    }

    /**
     * Accepting a medium is not accepting the critical it was re-scored to.
     * The other statuses make no claim about severity, so a re-score leaves
     * them standing.
     */
    private function exceedsAcceptedSeverity(Assessment $assessment, Finding $finding): bool
    {
        if ($assessment->status !== Status::Affected) {
            return false;
        }

        if ($assessment->acceptedSeverity === null) {
            return true;
        }

        return $finding->advisory->severity->getPriority() > $assessment->acceptedSeverity->getPriority();
    }
}
