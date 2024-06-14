package com.spring_boot_backend.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.spring_boot_backend.entity.User;
import com.spring_boot_backend.service.UserService;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@RestController
@RequestMapping("/admin")
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class AdminController {

    private final UserService userService;

    public AdminController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/")
    public String helloAdminController() {
        return "Admin access level";
    }

    @GetMapping("/listusers")
    public ResponseEntity<List<User>> retriveAllUsers() {
        System.out.println("In AdminController.java - /listusers");
        List<User> allUsers = userService.getAllUsers();
        return new ResponseEntity<>(allUsers, HttpStatus.OK);
    }

    @DeleteMapping("/listusers/{userId}")
    public ResponseEntity<HttpStatus> deleteUsername(@PathVariable int userId) {
        userService.deleteUser(userId);
        return new ResponseEntity<HttpStatus>(HttpStatus.NO_CONTENT);
    }

}
