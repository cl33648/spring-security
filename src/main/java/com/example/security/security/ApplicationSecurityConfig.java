package com.example.security.security;

import com.example.security.auth.ApplicationUserService;
import com.example.security.jwt.JwtConfig;
import com.example.security.jwt.JwtTokenVerifier;
import com.example.security.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.SecretKey;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;
    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService, SecretKey secretKey, JwtConfig jwtConfig) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()

                /**JWT STATELESS AUTH**/
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()  //STATELESS session won't be stored in the db
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
                .addFilterAfter(new JwtTokenVerifier(secretKey, jwtConfig),
                        JwtUsernameAndPasswordAuthenticationFilter.class)  //register JwtTokenVerifier after JwtUsernameAndPasswordAuthFilter

             /**CSRF AUTH
                csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
                    //csrfTokenRepository(...) setting up the repository: how the csrf token is generated
                    //.withHttpOnlyFalse means cookie will be inaccessible from client side
                    //CookieCsrfTokenRepository sets the value of token, sets the cookie, set cookie security, and adds the cookie to the response
                    //csrf header name = "X-XSRF-TOKEN"
            **/
                .authorizeRequests() //want to authorize request

                /*
                * antMatcher() is a method of HttpSecurity
                * The authorizeRequests().antMatchers() is used to apply authorization to one or more paths you specify in antMatchers().
                * Such as permitAll() or hasRole('USER3')
                * */

                .antMatchers("/","index","/css/*","/js/*")  //don't need to specify the username, password
                .permitAll()                                          //will go to the main page (index.html) with localhost:8080

                .antMatchers("/api/**")               //only student role user can access localhost:8080/api/...,
                .hasRole(ApplicationUserRole.STUDENT.name())    //Role Based authentication to protect API from ADMIN ROLE

            /**ANT MATCHERS - PERMISSION BASED AUTH
                //User Roles who has permission of COURSE_WRITE can access and DELETE,POST,and PUT the data
                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
            **/

            /**ANT MATCHER - ROLE BASED AUTH
                //User Role of ADMIN and ADMINTRAINEE can have access to management api
                .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(), ApplicationUserRole.ADMINTRAINEE.name())  //implementing permission
            **/

                .anyRequest()                                                           //any request
                .authenticated();                                                       //must be authenticated (i.e. client must specify the username, password)

            /**FORM-BASED LOGIN
                .and()                                                                  //and the mechanism to authenticate the client is through basic authentication
                .formLogin()                                                            //FORM based Authentication
                    .loginPage("/login").permitAll()                                        //custom login page
                    .defaultSuccessUrl("/courses", true)              //redirect after successful login
                    .passwordParameter("password")
                    .usernameParameter("username")
                .and().rememberMe()                                                      //remembers user session for default 2 weeks
                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))    //overriding the cookie's default 2weeks to 21 days
                    .key("somethingverysecured")                                                //md5 hashing of username & expiration time
                    .rememberMeParameter("remember-me")
                .and()
                .logout()                                                                       //logging out
                    .logoutUrl("/logout")
                    .logoutRequestMatcher(                                                      //best practice to use HTTP POST on any action
                            new AntPathRequestMatcher("/logout", "GET"))      //that changes state to protect against CSRF attacks
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID","remember-me")                          //deletes the JSESSIONID and remember-me cookies
                    .logoutSuccessUrl("/login");                                        //after logging out, goes back to "/login" page
            **/

            /**BASiC Auth
                //.httpBasic();                                                 //BASIC AUTH on POSTMAN
            **/

    }

    /*
    * The @Bean annotation returns an object that spring registers as a bean in application context.
    * The logic inside the method is responsible for creating the instance.
    * */
    /* replaced by ApplicationUserService
    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails annaSmithUser = User.builder()
                .username("annasmith")
                .password(passwordEncoder.encode("password"))   //password must be encoded
                .roles(ApplicationUserRole.STUDENT.name())                 //ROLE_STUDENT
                .authorities(ApplicationUserRole.STUDENT.getGrantedAuthorities())
                .build();

        UserDetails lindaUser = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("password123"))//password must be encoded
                .roles(ApplicationUserRole.ADMIN.name())                   //ROLE_ADMIN
                .authorities(ApplicationUserRole.ADMIN.getGrantedAuthorities())
                .build();

        UserDetails tomUser = User.builder()
                .username("tom")
                .password(passwordEncoder.encode("password123"))//password must be encoded
                .roles(ApplicationUserRole.ADMINTRAINEE.name())            //ROLE_ADMINTRAINEE
                .authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(
                annaSmithUser,
                lindaUser,
                tomUser
        );
    }*/

    //configuring the daoAuthenticationProvider is the way to use the custom ApplicationUserService that implements the UserDetailsService
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }
}
