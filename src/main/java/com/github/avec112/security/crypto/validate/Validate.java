package com.github.avec112.security.crypto.validate;

import com.github.avec112.security.crypto.error.MultipleMissingArgumentsError;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.stream.Collectors;

@Slf4j
public class Validate {

    private Validate() {
    }

    public static void all(RunValidation...validations) throws MultipleMissingArgumentsError {
        Objects.requireNonNull(validations, "Argument validations cannot be null");

        final List<Throwable> failures = Arrays.stream(validations).map(runValidation -> {
            // runValidation != null check here
            try {
                runValidation.validate();
                return null; // return null
            } catch (Throwable e) {
                return e; // return exception
            }
        })
                .filter(Objects::nonNull) // remove nulls
                .collect(Collectors.toList()); // collect all exceptions

        if (failures.size() > 1) {
            MultipleMissingArgumentsError multipleFailuresError = new MultipleMissingArgumentsError("Validation errors", failures);
            Objects.requireNonNull(multipleFailuresError);
            failures.forEach(multipleFailuresError::addSuppressed);
            throw multipleFailuresError;
        } else if(failures.size() == 1) {
            final Throwable throwable = failures.get(0);
            if(throwable instanceof RuntimeException) {
                throw (RuntimeException) throwable;
            } else {
                log.error("Unknown exception not handled", throwable);
                throw new IllegalStateException("Unknown exception not handled. Found ", throwable);
            }
        }

    }

    public static void nonBlank(String argument, Supplier<? extends IllegalArgumentException> exceptionSupplier) {
        Objects.requireNonNull(exceptionSupplier, "Argument exceptionSupplier cannot be null");
        if(StringUtils.isBlank(argument)) {
            throw exceptionSupplier.get();
        }
    }

    public static void nonNull(Object argument, String argumentName) {
        org.apache.commons.lang3.Validate.notBlank(argumentName, "Argument argumentName cannot be null or blank");
        if(argument == null) {
            throw new NullPointerException("Argument " + argumentName + " cannot be null");
        }
    }

    public static void nonNull(Object argument, Supplier<? extends NullPointerException> exceptionSupplier) {
        Objects.requireNonNull(exceptionSupplier, "Argument exceptionSupplier cannot be null");
        if(argument == null) {
            throw exceptionSupplier.get();
        }
    }
}
