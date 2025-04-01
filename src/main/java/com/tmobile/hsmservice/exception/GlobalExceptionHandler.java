package com.tmobile.hsmservice.exception;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.HandlerMethodValidationException;

import com.google.gson.JsonObject;
import io.grpc.StatusRuntimeException;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;

@RestControllerAdvice
public class GlobalExceptionHandler {

	private Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);
	
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	@ExceptionHandler({ MethodArgumentNotValidException.class })
	public Map<String, String> handleValidationExceptions(MethodArgumentNotValidException ex) {
		logger.info("MethodArgumentNotValidException observed");
		Map<String, String> errors = new HashMap<>();
		ex.getBindingResult().getAllErrors().forEach((error) -> {
			if (error instanceof FieldError) {
				String fieldName = ((FieldError) error).getField();
				String errorMessage = error.getDefaultMessage();
				errors.put(fieldName, errorMessage);
			} else {
				String errorMessage = ((ObjectError) error).getDefaultMessage();
				errors.put("errorMessage", errorMessage);
			}
		});
		return errors;
	}

	@ResponseStatus(HttpStatus.BAD_REQUEST)
	@ExceptionHandler({ MissingServletRequestParameterException.class })
	public ResponseEntity<String> handleRequestParameterExceptions(MissingServletRequestParameterException ex) {
		logger.info("MissingServletRequestParameterException observed");
		JsonObject jsonObject = new JsonObject();
		jsonObject.addProperty("message", ex.getMessage());
		return new ResponseEntity<>(jsonObject.toString(), HttpStatus.BAD_REQUEST);
	}
	
	@ResponseStatus(HttpStatus.NOT_FOUND)
	@ExceptionHandler({ StatusRuntimeException.class })
	public ResponseEntity<String> handleStatusRuntimeExceptions(StatusRuntimeException ex) {
		logger.info("StatusRuntimeException observed");
		JsonObject jsonObject = new JsonObject();
		jsonObject.addProperty("message", ex.getMessage());
		return new ResponseEntity<>(jsonObject.toString(), HttpStatus.NOT_FOUND);
	}

	@ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(ConstraintViolationException.class)
    public List<String> handleConstraintValidationExceptions(ConstraintViolationException ex) {
		logger.info("ConstraintViolationException observed");
        List<String> errors = new ArrayList<>();
        for (ConstraintViolation<?> violation : ex.getConstraintViolations()) {
            errors.add(violation.getMessage());
        }
        return errors;
    }
	
	@ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<String> handleConstraintValidationExceptions(IllegalArgumentException ex) {
		logger.info("IllegalArgumentException observed");
		JsonObject jsonObject = new JsonObject();
		jsonObject.addProperty("message", ex.getMessage());
		return new ResponseEntity<>(jsonObject.toString(), HttpStatus.BAD_REQUEST);
    }
	
	@ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(HandlerMethodValidationException.class)
    public Map<String, String> handleExceptions(HandlerMethodValidationException ex) {
		logger.info("HandlerMethodValidationException observed");
		
		Map<String, String> errors = new HashMap<>();
		ex.getAllErrors().forEach((error) -> {
			if (error instanceof FieldError) {
				String fieldName = ((FieldError) error).getField();
				String errorMessage = error.getDefaultMessage();
				errors.put(fieldName, errorMessage);
			} else {
				String errorMessage = ((ObjectError) error).getDefaultMessage();
				errors.put("errorMessage", errorMessage);
			}
		});
		return errors;
	}
	
	@ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(NoSuchElementException.class)
    public ResponseEntity<String> handleExceptions(NoSuchElementException ex) {
		logger.info("NoSuchElementException observed");
		ex.printStackTrace();
		JsonObject jsonObject = new JsonObject();
		jsonObject.addProperty("message", ex.getMessage());
		return new ResponseEntity<>(jsonObject.toString(), HttpStatus.BAD_REQUEST);
		
	}
}
