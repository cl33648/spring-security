package com.example.security.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/students")
/*to map URLs "api/v1/students" onto an entire class 'StudentController' by using a method*/
public class StudentController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "James Bond"),
            new Student(2, "Maria Jones"),
            new Student(3, "Anna Smith")
    );

    /*  composed annotation that acts as a shortcut for @RequestMapping(method = RequestMethod.GET).
        it is to be used only on method level
        so when 'studentId' is provided in the web request url/api 'http://localhost:8080/api/v1/students/{studentId}'
        it returns the following row data from the db*/
    @GetMapping(path = "{studentId}")
    public Student getStudent(@PathVariable("studentId") Integer studentId){
        return STUDENTS.stream().
                filter(student -> studentId.equals(student.getStudentId())).findFirst().
                orElseThrow(() -> new IllegalStateException("Student "+studentId+" does not exist"));
    }
}
