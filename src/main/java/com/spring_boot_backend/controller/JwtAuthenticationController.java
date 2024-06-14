package com.spring_boot_backend.controller;

import java.util.HashSet;
import java.util.Set;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.spring_boot_backend.entity.Authority;
import com.spring_boot_backend.entity.User;
import com.spring_boot_backend.record.JwtTokenRequest;
import com.spring_boot_backend.record.JwtTokenResponse;
import com.spring_boot_backend.repository.AuthorityRepository;
import com.spring_boot_backend.repository.UserRepository;
import com.spring_boot_backend.service.JwtTokenService;

@RestController
@RequestMapping("/authenticate")
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class JwtAuthenticationController {

    private final UserRepository userRepository;
    private final AuthorityRepository authorityRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenService tokenService;
    private final AuthenticationManager authenticationManager;

    public JwtAuthenticationController(UserRepository userRepository, AuthorityRepository authorityRepository,
            PasswordEncoder passwordEncoder,
            JwtTokenService tokenService,
            AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.authorityRepository = authorityRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/register")
    public void registerUser(@RequestBody JwtTokenRequest jwtTokenRequest) {
        String encodedPassword = passwordEncoder.encode(jwtTokenRequest.password());

        Authority userAuthority = authorityRepository.findByAuthority("USER").get();

        Set<Authority> authorities = new HashSet<>();

        authorities.add(userAuthority);

        userRepository.save(new User(0, jwtTokenRequest.username(), encodedPassword, authorities));

    }

    @PostMapping("/login")
    public ResponseEntity<JwtTokenResponse> loginUser(@RequestBody JwtTokenRequest jwtTokenRequest) {
        var authenticateToken = new UsernamePasswordAuthenticationToken(jwtTokenRequest.username(),
                jwtTokenRequest.password());

        var authentication = authenticationManager.authenticate(authenticateToken);

        var token = tokenService.generateJwtToken(authentication);

        return ResponseEntity.ok(new JwtTokenResponse(token));
    }
}
