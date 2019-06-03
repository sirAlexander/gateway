package com.shikanga.gateway.controller;

import com.shikanga.gateway.auth.AuthResponse;
import com.shikanga.gateway.auth.LoginRequest;
import com.shikanga.gateway.service.LoginService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@Controller
@RequestMapping("/api")
public class LoginController {

    @Autowired
    private LoginService loginService;

    @CrossOrigin("*")
    @PostMapping("/sign-in")
    @ResponseBody
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest loginRequest) {
        String token = loginService.login(loginRequest.getUsername(), loginRequest.getPassword());

        HttpHeaders httpHeaders = getHttpHeaders(token);

        return new ResponseEntity<>(new AuthResponse(token), httpHeaders, HttpStatus.CREATED);
    }

    @CrossOrigin("*")
    @PostMapping("/sign-out")
    @ResponseBody
    public ResponseEntity<AuthResponse> logout(@RequestHeader(value = "Authorization") String token) {

        HttpHeaders httpHeaders = new HttpHeaders();
        if (loginService.logout(token)) {
            httpHeaders.remove("Authorization");
            return new ResponseEntity<>(new AuthResponse("logged out"), httpHeaders, HttpStatus.CREATED);
        }

        return new ResponseEntity<>(new AuthResponse("Logout Failed"), httpHeaders, HttpStatus.NOT_MODIFIED);
    }

    /**
     * @param token
     * @return boolean
     * <p>
     * if request reaches this far, means we have a valid token
     */
    public boolean isValidToken(@RequestHeader(value = "Authorization") String token) {
        return true;
    }

    @CrossOrigin("*")
    @PostMapping("/sign-in/token")
    @ResponseBody
    public ResponseEntity<AuthResponse> createNewToken(@RequestHeader(value = "Authorization") String token) {
        String newToken = loginService.createNewToken(token);

        HttpHeaders httpHeaders = getHttpHeaders(newToken);

        return new ResponseEntity<>(new AuthResponse(newToken), httpHeaders, HttpStatus.CREATED);
    }

    private HttpHeaders getHttpHeaders(String token) {
        HttpHeaders httpHeaders = new HttpHeaders();

        List<String> headerList = new ArrayList<>();
        headerList.add("Content-Type");
        headerList.add("Accept");
        headerList.add("X-Requested-With");
        headerList.add("Authorization");
        httpHeaders.setAccessControlAllowHeaders(headerList);

        List<String> exposeList = new ArrayList<>();
        exposeList.add("Authorization");
        httpHeaders.setAccessControlExposeHeaders(exposeList);
        httpHeaders.set("Authorization", token);
        return httpHeaders;
    }
}
