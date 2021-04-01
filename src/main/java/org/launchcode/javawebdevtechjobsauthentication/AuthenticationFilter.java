package org.launchcode.javawebdevtechjobsauthentication;

import org.launchcode.javawebdevtechjobsauthentication.controllers.AuthenticationController;
import org.launchcode.javawebdevtechjobsauthentication.models.User;
import org.launchcode.javawebdevtechjobsauthentication.models.data.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;


public class AuthenticationFilter extends HandlerInterceptorAdapter {

    @Autowired
    UserRepository userRepository;

    @Autowired
    AuthenticationController authenticationController;

//  define whitelist  =list of items that are NOT subject to a given restriction
    private static final List<String> whitelist = Arrays.asList("/login", "/register", "/logout", "/css");

    // check whether or not a given request is whitelisted
    private static boolean isWhitelisted(String path) {
        for (String pathRoot : whitelist) {
            if (path.startsWith(pathRoot)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) throws IOException {

        // Don't require sign-in for whitelisted pages
        if (isWhitelisted(request.getRequestURI())) {
            // returning true indicates that the request may proceed
            return true;
        }

//        Retrieves the user’s session object, which is contained in the request.
        HttpSession session = request.getSession();
        User user = authenticationController.getUserFromSession(session); //Retrieves the User object corresponding to the given user. Recall that this will be null if the user is not logged in.

        //The user object is non-null, so the user is logged in. Allow the request to be handled as normal.
        // The user is logged in
        if (user != null) {
            return true;
        }

        //The user object is null, so we redirect the user to the login page.
        // The user is NOT logged in
        response.sendRedirect("/login");
        return false;



    }

}