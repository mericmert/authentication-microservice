package com.mericbulca.usermicroservice.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mericbulca.usermicroservice.controllers.AuthenticationRequest;
import com.mericbulca.usermicroservice.controllers.RegisterRequest;
import com.mericbulca.usermicroservice.controllers.AuthenticationResponse;
import com.mericbulca.usermicroservice.repository.UserRepository;
import com.mericbulca.usermicroservice.token.Token;
import com.mericbulca.usermicroservice.token.TokenRepository;
import com.mericbulca.usermicroservice.token.TokenType;
import com.mericbulca.usermicroservice.user.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest req){
        User user = User.builder()
                .username(req.getUsername())
                .email(req.getEmail())
                .full_name(req.getFull_name())
                .password(passwordEncoder.encode(req.getPassword()))
                .role(req.getRole())
                .build();
        User savedUser = userRepository.save(user);
        String token = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        saveUserToken(savedUser, token);

        return AuthenticationResponse.builder()
                .accessToken(token)
                .refreshToken(refreshToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest authRequest) {

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authRequest.getUsername(),
                        authRequest.getPassword()
                )
        );
        User user = userRepository.findUserByUsername(authRequest.getUsername())
                .orElseThrow();

        final String jwtToken = jwtService.generateToken(user);
        final String refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();


    }


    private void saveUserToken(User user, String jwtToken){
        Token token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();

        tokenRepository.save(token);
    }


    public void refreshToken(HttpServletRequest req, HttpServletResponse res) throws IOException {
        final String authHeader = req.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String username;
        if (authHeader == null || !authHeader.startsWith("Bearer ")){
            return;
        }
        refreshToken = authHeader.substring(7);
        username = jwtService.extractUsername(refreshToken);
        if (username != null){
            User user = userRepository.findUserByUsername(username)
                    .orElseThrow();
            if(jwtService.isTokenValid(refreshToken, user)){
                String accessToken = jwtService.generateToken(user);
                revokeAllUserTokens(user);
                saveUserToken(user, accessToken);
                AuthenticationResponse authResponse = AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();
                new ObjectMapper().writeValue(res.getOutputStream(), authResponse);
            }
        }

    }

    private void revokeAllUserTokens(User user) {

        List<Token> allValidTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (allValidTokens.isEmpty()){
            return;
        }
        allValidTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });

        tokenRepository.saveAll(allValidTokens);

    }

}
