package com.jwt.jwtdemo.controller;

import com.jwt.jwtdemo.domain.dto.SignRequest;
import com.jwt.jwtdemo.domain.dto.SignResponse;
import com.jwt.jwtdemo.repository.MemberRepository;
import com.jwt.jwtdemo.service.SignService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class SignController {

    private final SignService memberService;

    @PostMapping("/login")
    private ResponseEntity<SignResponse> signIn(@RequestBody SignRequest request) throws Exception {
        return new ResponseEntity<>(memberService.login(request), HttpStatus.OK);
    }

    @PostMapping("/register")
    private ResponseEntity<Boolean> signUp(@RequestBody SignRequest request) throws Exception {
        return new ResponseEntity<>(memberService.register(request), HttpStatus.OK);
    }

    @GetMapping("/user/get")
    private ResponseEntity<SignResponse> getUser(@RequestBody String account) throws Exception {
        return new ResponseEntity<>(memberService.getMember(account), HttpStatus.OK);
    }

    @GetMapping("/admin/get")
    private ResponseEntity<SignResponse> getUserForAdmin(@RequestBody String account) throws Exception {
        return new ResponseEntity<>(memberService.getMember(account), HttpStatus.OK);
    }
}
