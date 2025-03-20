package com.example.login_test;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserEntity {
    @Column(unique = true)
    private String email;
    private String password;
    private String name;
    private String role;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
}
