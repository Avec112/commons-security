package io.github.avec112.security.crypto.error;

import org.opentest4j.MultipleFailuresError;

import java.util.List;

// TODO write own class MultipleMissingArgumentsException replacing MultipleMissingArgumentsError without dependency to opentest4j and only throwing/supporting RuntimeException
public class MultipleMissingArgumentsError extends MultipleFailuresError {
    public MultipleMissingArgumentsError(String heading, List<? extends Throwable> failures) {
        super(heading, failures);
    }
}
