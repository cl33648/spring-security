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

