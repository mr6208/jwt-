package com.jwt.jwtdemo.service;

import com.jwt.jwtdemo.domain.Authority;
import com.jwt.jwtdemo.domain.Member;
import com.jwt.jwtdemo.domain.dto.SignRequest;
import com.jwt.jwtdemo.domain.dto.SignResponse;
import com.jwt.jwtdemo.repository.MemberRepository;
import com.jwt.jwtdemo.security.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;

@Service
@Transactional
@RequiredArgsConstructor
public class SignService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;

    public SignResponse login(SignRequest request) throws Exception {
        Member member = memberRepository.findByAccount(request.getAccount()).orElseThrow(()
                -> new BadCredentialsException("잘못된 계정정보입니다."));

        if (!passwordEncoder.matches(request.getPassword(), member.getPassword())) {
            throw new BadCredentialsException("잘못된 계정정보입니다.");
        }
        return SignResponse.builder()
                .id(member.getId())
                .account(member.getAccount())
                .relation(member.getRelation())
                .name(member.getName())
                .nickname(member.getNickname())
                .email(member.getEmail())
                .roles(member.getRoles())
                .token(jwtProvider.createToken(member.getAccount(), member.getRoles()))
                .build();
    }

    public boolean register(SignRequest request) throws Exception {
        try {
            Member member = Member.builder()
                    .account(request.getAccount())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .nickname(request.getNickname())
                    .relation(request.getRelation())
                    .name(request.getName())
                    .email(request.getEmail())
                    .build();

            member.setRoles(Collections.singletonList(Authority.builder().name("ROLE_USER").build()));

            memberRepository.save(member);
        } catch (Exception e) {
            throw new Exception("잘못된 요청");
        }
        return true;
    }

    public SignResponse getMember(String account) {
        Member member = memberRepository.findByAccount(account)
                .orElseThrow(() -> new RuntimeException("계정을 찾을 수 없습니다."));
        return new SignResponse(member);
    }
}
