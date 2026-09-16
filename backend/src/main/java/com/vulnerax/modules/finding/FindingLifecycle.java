package com.vulnerax.modules.finding;

import java.util.Map;
import java.util.Set;
import static java.util.Map.entry;

public class FindingLifecycle {

    public enum Status {
        OBSERVED,
        SUSPECTED,
        VALIDATED,
        CONFIRMED,
        OPEN,
        IN_PROGRESS,
        REMEDIATED,
        RETESTING,
        VERIFIED_FIXED,
        CLOSED,
        // Branch states
        FALSE_POSITIVE,
        ACCEPTED_RISK,
        DUPLICATE,
        SUPPRESSED,
        NOT_APPLICABLE
    }

    private static final Map<Status, Set<Status>> TRANSITIONS = Map.ofEntries(
            entry(Status.OBSERVED, Set.of(Status.SUSPECTED, Status.FALSE_POSITIVE, Status.NOT_APPLICABLE)),
            entry(Status.SUSPECTED, Set.of(Status.VALIDATED, Status.FALSE_POSITIVE, Status.NOT_APPLICABLE)),
            entry(Status.VALIDATED, Set.of(Status.CONFIRMED, Status.FALSE_POSITIVE)),
            entry(Status.CONFIRMED, Set.of(Status.OPEN, Status.ACCEPTED_RISK, Status.SUPPRESSED)),
            entry(Status.OPEN, Set.of(Status.IN_PROGRESS, Status.ACCEPTED_RISK, Status.SUPPRESSED, Status.DUPLICATE)),
            entry(Status.IN_PROGRESS, Set.of(Status.REMEDIATED, Status.OPEN)),
            entry(Status.REMEDIATED, Set.of(Status.RETESTING)),
            entry(Status.RETESTING, Set.of(Status.VERIFIED_FIXED, Status.OPEN)),
            entry(Status.VERIFIED_FIXED, Set.of(Status.CLOSED)),
            entry(Status.CLOSED, Set.of()),
            entry(Status.FALSE_POSITIVE, Set.of(Status.OPEN)),
            entry(Status.ACCEPTED_RISK, Set.of(Status.OPEN)),
            entry(Status.DUPLICATE, Set.of(Status.OPEN)),
            entry(Status.SUPPRESSED, Set.of(Status.OPEN)),
            entry(Status.NOT_APPLICABLE, Set.of(Status.OPEN))
    );

    public static boolean canTransition(Status from, Status to) {
        return TRANSITIONS.containsKey(from) && TRANSITIONS.get(from).contains(to);
    }

    public static String getTransitionMessage(Status from, Status to) {
        if (!canTransition(from, to)) {
            return "Invalid transition: " + from + " -> " + to;
        }
        return switch (to) {
            case FALSE_POSITIVE -> "Marked as false positive";
            case ACCEPTED_RISK -> "Accepted as risk";
            case DUPLICATE -> "Marked as duplicate";
            case SUPPRESSED -> "Suppressed";
            case NOT_APPLICABLE -> "Not applicable";
            case REMEDIATED -> "Fix applied by developer";
            case RETESTING -> "Retest in progress";
            case VERIFIED_FIXED -> "Fix verified via retest";
            case CLOSED -> "Finding closed";
            default -> "Status updated to " + to;
        };
    }
}
