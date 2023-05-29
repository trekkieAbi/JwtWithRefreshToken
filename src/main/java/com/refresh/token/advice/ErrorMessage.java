package com.refresh.token.advice;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;
@AllArgsConstructor
@Getter
@Setter
public class ErrorMessage {
    private int statuscode;
    private Date timeStamp;
    private String message;

    private String description;



}
