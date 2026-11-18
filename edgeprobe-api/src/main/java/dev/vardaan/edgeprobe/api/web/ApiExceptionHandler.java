package dev.vardaan.edgeprobe.api.web;

import dev.vardaan.edgeprobe.api.scan.ScanNotFoundException;
import dev.vardaan.edgeprobe.core.net.BlockedTargetException;
import dev.vardaan.edgeprobe.core.net.InvalidTargetException;
import dev.vardaan.edgeprobe.core.net.UnresolvableHostException;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/** Maps domain errors to RFC 9457 problem details (application/problem+json). */
@RestControllerAdvice
public class ApiExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(InvalidTargetException.class)
    ProblemDetail invalidTarget(InvalidTargetException e) {
        return problem(HttpStatus.BAD_REQUEST, "Invalid URL", e.getMessage());
    }

    @ExceptionHandler(BlockedTargetException.class)
    ProblemDetail blockedTarget(BlockedTargetException e) {
        return problem(HttpStatus.UNPROCESSABLE_CONTENT, "Target not allowed", e.getMessage());
    }

    @ExceptionHandler(UnresolvableHostException.class)
    ProblemDetail unresolvable(UnresolvableHostException e) {
        return problem(HttpStatus.UNPROCESSABLE_CONTENT, "Host does not resolve", e.getMessage());
    }

    @ExceptionHandler(ScanNotFoundException.class)
    ProblemDetail notFound(ScanNotFoundException e) {
        return problem(HttpStatus.NOT_FOUND, "Scan not found", e.getMessage());
    }

    @ExceptionHandler(ConstraintViolationException.class)
    ProblemDetail constraintViolation(ConstraintViolationException e) {
        return problem(HttpStatus.BAD_REQUEST, "Invalid request", e.getMessage());
    }

    private static ProblemDetail problem(HttpStatus status, String title, String detail) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setTitle(title);
        return problem;
    }
}
