package com.vulnerax.common.exception;

import com.vulnerax.common.ApiResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.http.HttpMethod;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class GlobalExceptionHandlerTest {

    @InjectMocks
    GlobalExceptionHandler handler;

    @Test
    void handleNotFound_resourceNotFound_returns404() {
        ResourceNotFoundException ex = new ResourceNotFoundException("User not found");

        ResponseEntity<ApiResponse<?>> response = handler.handleNotFound(ex);

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertFalse(response.getBody().isSuccess());
        assertEquals("User not found", response.getBody().getMessage());
    }

    @Test
    void handleBusiness_businessException_returns400() {
        BusinessException ex = new BusinessException("Insufficient funds");

        ResponseEntity<ApiResponse<?>> response = handler.handleBusiness(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertFalse(response.getBody().isSuccess());
        assertEquals("Insufficient funds", response.getBody().getMessage());
    }

    @Test
    void handleValidation_withFieldErrors_returns400WithErrors() {
        MethodArgumentNotValidException ex = mock(MethodArgumentNotValidException.class);
        BindingResult bindingResult = mock(BindingResult.class);
        FieldError fieldError = new FieldError("user", "email", "must be valid email");
        when(ex.getBindingResult()).thenReturn(bindingResult);
        when(bindingResult.getFieldErrors()).thenReturn(List.of(fieldError));

        ResponseEntity<ApiResponse<?>> response = handler.handleValidation(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertFalse(response.getBody().isSuccess());
    }

    @Test
    void handleValidation_emptyErrors_returnsGenericMessage() {
        MethodArgumentNotValidException ex = mock(MethodArgumentNotValidException.class);
        BindingResult bindingResult = mock(BindingResult.class);
        when(ex.getBindingResult()).thenReturn(bindingResult);
        when(bindingResult.getFieldErrors()).thenReturn(List.of());

        ResponseEntity<ApiResponse<?>> response = handler.handleValidation(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertFalse(response.getBody().isSuccess());
    }

    @Test
    void handleValidation_duplicateFieldErrors_takesFirst() {
        MethodArgumentNotValidException ex = mock(MethodArgumentNotValidException.class);
        BindingResult bindingResult = mock(BindingResult.class);
        FieldError fe1 = new FieldError("user", "email", "invalid");
        FieldError fe2 = new FieldError("user", "email", "duplicate");
        when(ex.getBindingResult()).thenReturn(bindingResult);
        when(bindingResult.getFieldErrors()).thenReturn(List.of(fe1, fe2));

        ResponseEntity<ApiResponse<?>> response = handler.handleValidation(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }

    @Test
    void handleMissingParam_returns400() {
        MissingServletRequestParameterException ex = mock(MissingServletRequestParameterException.class);
        when(ex.getParameterName()).thenReturn("projectId");

        ResponseEntity<ApiResponse<?>> response = handler.handleMissingParam(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertFalse(response.getBody().isSuccess());
        assertTrue(response.getBody().getMessage().contains("projectId"));
    }

    @Test
    void handleTypeMismatch_returns400() {
        MethodArgumentTypeMismatchException ex = mock(MethodArgumentTypeMismatchException.class);
        when(ex.getName()).thenReturn("id");

        ResponseEntity<ApiResponse<?>> response = handler.handleTypeMismatch(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertFalse(response.getBody().isSuccess());
        assertTrue(response.getBody().getMessage().contains("id"));
    }

    @Test
    void handleAccess_returns403() {
        AccessDeniedException ex = new AccessDeniedException("Forbidden");

        ResponseEntity<ApiResponse<?>> response = handler.handleAccess(ex);

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertFalse(response.getBody().isSuccess());
        assertEquals("Access denied", response.getBody().getMessage());
    }

    @Test
    void handleBadCredentials_returns401() {
        BadCredentialsException ex = new BadCredentialsException("Wrong password");

        ResponseEntity<ApiResponse<?>> response = handler.handleBadCredentials(ex);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertFalse(response.getBody().isSuccess());
        assertEquals("Invalid email or password", response.getBody().getMessage());
    }

    @Test
    void handleUserNotFound_returns401() {
        UsernameNotFoundException ex = new UsernameNotFoundException("user@example.com");

        ResponseEntity<ApiResponse<?>> response = handler.handleUserNotFound(ex);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertFalse(response.getBody().isSuccess());
        assertEquals("User not found", response.getBody().getMessage());
    }

    @Test
    void handleDataIntegrity_duplicateKey_returns409() {
        DataIntegrityViolationException ex = new DataIntegrityViolationException(
                "duplicate key value violates unique constraint");

        ResponseEntity<ApiResponse<?>> response = handler.handleDataIntegrity(ex);

        assertEquals(HttpStatus.CONFLICT, response.getStatusCode());
        assertFalse(response.getBody().isSuccess());
        assertEquals("Record already exists", response.getBody().getMessage());
    }

    @Test
    void handleDataIntegrity_nonDuplicate_returns409() {
        DataIntegrityViolationException ex = new DataIntegrityViolationException(
                "foreign key constraint violation");

        ResponseEntity<ApiResponse<?>> response = handler.handleDataIntegrity(ex);

        assertEquals(HttpStatus.CONFLICT, response.getStatusCode());
        assertFalse(response.getBody().isSuccess());
        assertEquals("Data integrity violation", response.getBody().getMessage());
    }

    @Test
    void handleDataIntegrity_nullMessage_returns409() {
        DataIntegrityViolationException ex = new DataIntegrityViolationException("error", null);

        ResponseEntity<ApiResponse<?>> response = handler.handleDataIntegrity(ex);

        assertEquals(HttpStatus.CONFLICT, response.getStatusCode());
    }

    @Test
    void handleMethodNotSupported_returns405() {
        HttpRequestMethodNotSupportedException ex = new HttpRequestMethodNotSupportedException("DELETE");

        ResponseEntity<ApiResponse<?>> response = handler.handleMethodNotSupported(ex);

        assertEquals(HttpStatus.METHOD_NOT_ALLOWED, response.getStatusCode());
        assertFalse(response.getBody().isSuccess());
        assertTrue(response.getBody().getMessage().contains("DELETE"));
    }

    @Test
    void handleMaxUpload_returns413() {
        MaxUploadSizeExceededException ex = new MaxUploadSizeExceededException(50 * 1024 * 1024L);

        ResponseEntity<ApiResponse<?>> response = handler.handleMaxUpload(ex);

        assertEquals(HttpStatus.PAYLOAD_TOO_LARGE, response.getStatusCode());
        assertFalse(response.getBody().isSuccess());
        assertTrue(response.getBody().getMessage().contains("File too large"));
    }

    @Test
    void handleNotFound_noResourceFound_returns404() {
        NoResourceFoundException ex = new NoResourceFoundException(HttpMethod.GET, "/api/v1/missing");

        ResponseEntity<ApiResponse<?>> response = handler.handleNotFound(ex);

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertFalse(response.getBody().isSuccess());
        assertEquals("Resource not found", response.getBody().getMessage());
    }

    @Test
    void handleOther_genericException_returns500() {
        Exception ex = new RuntimeException("Something unexpected");

        ResponseEntity<ApiResponse<?>> response = handler.handleOther(ex);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertFalse(response.getBody().isSuccess());
        assertEquals("Something unexpected", response.getBody().getMessage());
    }

    @Test
    void handleOther_nullMessage_returnsDefaultError() {
        Exception ex = new RuntimeException((String) null);

        ResponseEntity<ApiResponse<?>> response = handler.handleOther(ex);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals("Internal server error", response.getBody().getMessage());
    }

    @Test
    void handleOther_emptyMessage_returnsDefaultError() {
        Exception ex = new RuntimeException("");

        ResponseEntity<ApiResponse<?>> response = handler.handleOther(ex);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals("Internal server error", response.getBody().getMessage());
    }

    @Test
    void allResponsesHaveApiResponseStructure() {
        ResourceNotFoundException notFound = new ResourceNotFoundException("test");
        ResponseEntity<ApiResponse<?>> r1 = handler.handleNotFound(notFound);
        assertNotNull(r1.getBody());
        assertNotNull(r1.getBody().isSuccess());

        BusinessException biz = new BusinessException("test");
        ResponseEntity<ApiResponse<?>> r2 = handler.handleBusiness(biz);
        assertNotNull(r2.getBody());

        AccessDeniedException access = new AccessDeniedException("test");
        ResponseEntity<ApiResponse<?>> r3 = handler.handleAccess(access);
        assertNotNull(r3.getBody());

        BadCredentialsException creds = new BadCredentialsException("test");
        ResponseEntity<ApiResponse<?>> r4 = handler.handleBadCredentials(creds);
        assertNotNull(r4.getBody());

        Exception generic = new Exception("test");
        ResponseEntity<ApiResponse<?>> r5 = handler.handleOther(generic);
        assertNotNull(r5.getBody());
    }

    @Test
    void handleDataIntegrity_duplicateWithDifferentMessage() {
        DataIntegrityViolationException ex = new DataIntegrityViolationException(
                "ERROR: duplicate entry 'abc' for key 'unique_name'");

        ResponseEntity<ApiResponse<?>> response = handler.handleDataIntegrity(ex);

        assertEquals("Record already exists", response.getBody().getMessage());
    }
}
