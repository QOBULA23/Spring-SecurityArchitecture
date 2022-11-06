package com.example.springsecurityarchitecture;

import lombok.Data;
import org.apache.catalina.connector.Request;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class SpringSecurityArchitectureApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityArchitectureApplication.class, args);
    }

    @Bean
    BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}

@RestController
class BasicController{

    @Autowired
    JwtUtil jwtUtil;

    @Autowired
    AuthenticationManager authenticationManager;

    @GetMapping("/hello")
    public ResponseEntity<String> hello(){
        return ResponseEntity.ok("Hello World!");
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginDTO loginDTO){
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(loginDTO.getUsername(), loginDTO.getPassword());
        authenticationManager.authenticate(token);
        String jwtToken = jwtUtil.generate(loginDTO.getUsername());
        return ResponseEntity.ok(jwtToken);
    }
}

@Data
class LoginDTO{
    private String username;
    private String password;
}

@Configuration
@EnableWebSecurity
class WebSecurity extends WebSecurityConfigurerAdapter {

    @Autowired
    JwtTokenFIlter jwtTokenFIlter;

    @Autowired
    JwtAuthenticationProvider jwtAuthenticationProvider;

    @Autowired
    GoogleCloudAuthenticationProvider googleCloudAuthenticationProvider;



    @Bean
    public AuthenticationManager getAuthenticationManager() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(jwtAuthenticationProvider)
                .authenticationProvider(googleCloudAuthenticationProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeHttpRequests().antMatchers("/login").permitAll().anyRequest().authenticated()
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.addFilterBefore(jwtTokenFIlter, UsernamePasswordAuthenticationFilter.class);
    }
}


@Service
class UserDetailsServiceImpl implements UserDetailsService {

        @Autowired
        PasswordEncoder encoder;

        @Override
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
            Map<String, String> map = new HashMap<>();
            map.put("martin", encoder.encode("123"));
            if (map.containsKey(username)) {
                return new User(username, map.get(username), new ArrayList<>());
            }
            throw new UsernameNotFoundException(username);
        }
}

@Service
class JwtTokenFIlter extends OncePerRequestFilter{

    @Autowired
    JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // Authorization Bearer token
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader == null || authorizationHeader.isEmpty() || !authorizationHeader.startsWith("Bearer")){
            filterChain.doFilter(request, response);
            return;
        }
        // Bearer token
        String token = authorizationHeader.split(" ")[1].trim();
        if (jwtUtil.validate(token)){
            filterChain.doFilter(request, response);
            return;
        }

        String username = jwtUtil.getUsername(token);
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, null, new ArrayList<>());
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}

@Service
class JwtAuthenticationProvider implements AuthenticationProvider{

    @Qualifier("userDetailsServiceImpl")
    @Autowired
    UserDetailsService userDetailsService;

    @Autowired
    PasswordEncoder encoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = String.valueOf(authentication.getPrincipal());
        String password = String.valueOf(authentication.getCredentials());
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        if(userDetails != null){
            if (encoder.matches(password, userDetails.getPassword())){
              UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password, new ArrayList<>());
              return token;
            }
        }

        throw new BadCredentialsException("Error!");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.equals(authentication);
    }
}

@Service
class GoogleCloudAuthenticationProvider implements AuthenticationProvider{


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = String.valueOf(authentication.getPrincipal());
        String password = String.valueOf(authentication.getCredentials());

        User userGoogleCloud = getUserGoogleCloud(username, password);

        if (userGoogleCloud !=null){
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password, new ArrayList<>());
            return token;
        }

        throw new BadCredentialsException("Error!");
    }

    private User getUserGoogleCloud(String username, String password) {


        Map<String, String> map = new HashMap<>();
        map.put("nika", "123");

        if (map.containsKey(username) && map.get(username).equals(password)){
            return new User(username, password, new ArrayList<>());
        }
        return null;
    }


    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.equals(authentication);
    }
}