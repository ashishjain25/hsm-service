package com.tmobile.hsmservice.exception;

import java.util.HashMap;
import java.util.Map;

import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.google.gson.JsonObject;

import io.grpc.StatusRuntimeException;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@RestControllerAdvice
public class GlobalExceptionHandler {

	@ResponseStatus(HttpStatus.BAD_REQUEST)
	@ExceptionHandler({ MethodArgumentNotValidException.class })
	public Map<String, String> handleValidationExceptions(MethodArgumentNotValidException ex) {
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
	public ResponseEntity<String> handleValidationExceptions(MissingServletRequestParameterException ex) {
		JsonObject jsonObject = new JsonObject();
		jsonObject.addProperty("message", ex.getMessage());
		//ErrorResponse response = ErrorResponse.builder(ex, ex.getBody()).build();
		return new ResponseEntity<>(jsonObject.toString(), HttpStatus.BAD_REQUEST);
	}
	
	@ResponseStatus(HttpStatus.NOT_FOUND)
	@ExceptionHandler({ StatusRuntimeException.class })
	public ResponseEntity<String> handleValidationExceptions(StatusRuntimeException ex) {
		JsonObject jsonObject = new JsonObject();
		jsonObject.addProperty("message", ex.getMessage());
		//ErrorResponse response = ErrorResponse.builder(ex, ex.getBody()).build();
		return new ResponseEntity<>(jsonObject.toString(), HttpStatus.NOT_FOUND);
	}

}
