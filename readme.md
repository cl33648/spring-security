#Spring Security

##Description
My personal learning project of Spring Security

#Form Based Authentication
![](diagram/Form-Based-Auth.png)  
Session ID is stored in in-memory database by Spring  
It can also be stored in Postgres, Redis, etc.  
Everytime the Application is reset, the Session ID will be lost and reset with new value, in case of in-memory db.  
Best practice is to implement real database server.  

#Custom Login Page 
![](diagram/custom-login.png)  
Custom Login Page is implemented by using thymeleaf.  
TemplateController.java, along with login.html and courses.html are implemented.  
Redirect to '/courses' page and remember-me are implemented in configure method of ApplicationSecurityConfig.java.  

#Logout
If CSRF protection is enabled (default), then the request mest be also be a POST.  
This means that by default POST "/logout" is required to trigger a logout.  
If CSRF protection is disabled, then any http method is allowed.  
It is considered best pracrice to use an HTTP POST on any action that changes state to protect against CSRF attacks.  
To use HTTP GET, use logoutRequestMatcher(new AntPathRequestMatcher(logoutUrl, "GET"));  
ApplicationSecurityConfig.java - configure method  
![](diagram/login-url.png)  
Logout button is added on the courses.html (localhost:8080/courses)  
![](diagram/logout-courses.png)  