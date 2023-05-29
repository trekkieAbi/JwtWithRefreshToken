package com.refresh.token.advice;


import com.refresh.token.exception.TokenRefreshException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.util.Date;

@RestControllerAdvice
public class TokenControllerAdvice {
    @ExceptionHandler(value = TokenRefreshException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ErrorMessage handleTokenRefreshException(TokenRefreshException tokenRefreshException, WebRequest webRequest){
        return new ErrorMessage(HttpStatus.FORBIDDEN.value(),new Date(), tokenRefreshException.getMessage(), webRequest.getDescription(false));
    }
}
