package com.mericbulca.usermicroservice.controllers;

import com.mericbulca.usermicroservice.user.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {
    private String username;
    private String full_name;
    private String email;
    private String password;
    private Role role;

}
