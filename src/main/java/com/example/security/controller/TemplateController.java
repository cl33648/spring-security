package com.example.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/")
public class TemplateController {

    //once we hit the login page(localhost:8080/login) on the browser, bring in login.html
    @GetMapping("login")
    public String getLoginView(){
        return "login";
    }

    //after logging in, the courses page(localhost:8080/courses) on the browser, bring in the courses.html
    @GetMapping("courses")
    public String getCourses(){
        return "courses";
    }
}
