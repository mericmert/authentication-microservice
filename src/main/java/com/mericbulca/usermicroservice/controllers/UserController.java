package com.mericbulca.usermicroservice.controllers;


import com.mericbulca.usermicroservice.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
public class UserController {

    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest registerRequest){
        try {
            AuthenticationResponse res = userService.register(registerRequest);
            return ResponseEntity.ok(res);
        }
        catch (Exception e){
            return ResponseEntity.badRequest().body(null);
        }
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest authRequest){
        try{
            return ResponseEntity.ok(userService.authenticate(authRequest));
        }
        catch (Exception e){
            System.out.println(e.toString());
            return ResponseEntity.badRequest().body(null);
        }
    }



    @PostMapping("/refresh-token")
    public void refreshToken(HttpServletRequest req, HttpServletResponse res) throws Exception{
        userService.refreshToken(req, res);
    }



}
