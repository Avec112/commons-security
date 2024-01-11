package io.avec.security.crypto.validate;

import io.avec.security.crypto.error.MultipleMissingArgumentsError;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class Validate {

    private Validate() {
    }

    public static void all(RunValidation...validations) throws MultipleMissingArgumentsError {

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
                throwable.printStackTrace();
                throw new IllegalStateException("Unknown exception not handled. Found ", throwable);
            }
        }

    }

    public static void nonBlank(String argument, @NonNull Supplier<? extends IllegalArgumentException> exceptionSupplier) {
        if(StringUtils.isBlank(argument)) {
            throw exceptionSupplier.get();
        }
    }

    public static void nonBlank(String argument, @NonNull String argumentName) {
        nonBlank(argument, () -> new IllegalArgumentException(argumentName + " cannot be null or blank"));
    }

    public static void nonNull(Object argument, @NonNull String argumentName) {
        nonNull(argument, () -> new NullPointerException("Argument " + argumentName + " cannot be null"));
    }

    public static void nonNull(Object argument, @NonNull Supplier<? extends NullPointerException> exceptionSupplier) {
        if(argument == null) {
            throw exceptionSupplier.get();
        }
    }
}
