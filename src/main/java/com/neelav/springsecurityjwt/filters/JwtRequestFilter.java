package com.neelav.springsecurityjwt.filters;

import com.neelav.springsecurityjwt.services.MyUserDetailsService;
import com.neelav.springsecurityjwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import sun.plugin.liveconnect.SecurityContextHelper;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private MyUserDetailsService myUserDetailsService;

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //Getting the Authorization Token
        String authorizationHeader = request.getHeader("Authorization");

        String username=null;
        String jwt=null;

        //Checking whether the JWT token is Provided and extracting it
        if(authorizationHeader !=null && authorizationHeader.startsWith("Bearer "))
        {

            jwt = authorizationHeader.substring(7);
            username = jwtUtil.extractUsername(jwt);
        }

        //SecurityContextHolder.getContext().getAuthentication()==null ,is done so as to infer that authentication is not yet Completed
        if(username != null && SecurityContextHolder.getContext().getAuthentication()==null)
        {
            UserDetails userDetails = this.myUserDetailsService.loadUserByUsername(username);

            if(jwtUtil.validateToken(jwt,userDetails))
            {
                //Setting the UsernamePasswordAuthenticationToken since here we are responsible to handle the authorization/authentication
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails,null,userDetails.getAuthorities());

                usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                //Here we are establishing the fact that Authentication has been done
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }

        //Passing on the Next Filter
        filterChain.doFilter(request,response);


    }
}
