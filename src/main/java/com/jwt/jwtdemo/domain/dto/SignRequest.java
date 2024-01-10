package com.jwt.jwtdemo.domain.dto;

import com.jwt.jwtdemo.domain.Relation;
import lombok.Data;

@Data
public class SignRequest {

    private Long id;

    private String account;

    private Relation relation;

    private String password;

    private String nickname;

    private String name;

    private String email;
}
