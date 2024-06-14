package com.spring_boot_backend.service;

import java.util.List;

import com.spring_boot_backend.entity.User;

public interface UserService {

    List<User> getAllUsers();

    void deleteUser(int userId);

}
