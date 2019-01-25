/*
 *Copyright (C) 2018 Queensland Cyber Infrastructure Foundation (http://www.qcif.edu.au/)
 *
 *This program is free software: you can redistribute it and/or modify
 *it under the terms of the GNU General Public License as published by
 *the Free Software Foundation; either version 2 of the License, or
 *(at your option) any later version.
 *
 *This program is distributed in the hope that it will be useful,
 *but WITHOUT ANY WARRANTY; without even the implied warranty of
 *MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *GNU General Public License for more details.
 *
 *You should have received a copy of the GNU General Public License along
 *with this program; if not, write to the Free Software Foundation, Inc.,
 *51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package au.edu.qcif.xnat.auth.openid;

import au.edu.qcif.xnat.auth.openid.tokens.OpenIdAuthToken;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.nrg.framework.services.SerializerService;
import org.nrg.xdat.security.helpers.Users;
import org.nrg.xdat.security.user.exceptions.UserInitException;
import org.nrg.xdat.security.user.exceptions.UserNotFoundException;
import org.nrg.xft.event.EventDetails;
import org.nrg.xft.event.EventUtils;
import org.nrg.xft.security.UserI;
import org.nrg.xnat.security.exceptions.NewAutoAccountNotAutoEnabledException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Main Spring Security authentication filter.
 *
 * @author <a href='https://github.com/shilob'>Shilo Banihit</a>
 */
@Slf4j
public class OpenIdConnectFilter extends AbstractAuthenticationProcessingFilter {
    public OpenIdConnectFilter(final String defaultFilterProcessesUrl, final OpenIdAuthPlugin plugin, final SerializerService serializer) {
        super(defaultFilterProcessesUrl);
        log.debug("Created filter for " + defaultFilterProcessesUrl);
        setAuthenticationManager(new NoopAuthenticationManager());
        _plugin = plugin;
        _serializer = serializer;

        final String allowedEmailDomains = _plugin.getProperty("allowedEmailDomains");
        _allowedDomains = StringUtils.isNotBlank(allowedEmailDomains) ? Arrays.asList(allowedEmailDomains.toLowerCase().split("\\s*,\\s*")) : Collections.<String>emptyList();
    }

    @Autowired
    @Qualifier("xnatOAuth2RestTemplate")
    public void setOAuth2RestTemplate(final OAuth2RestTemplate oAuth2RestTemplate) {
        _oAuth2RestTemplate = oAuth2RestTemplate;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {
        log.debug("Executed attemptAuthentication...");
        final OAuth2AccessToken accessToken;
        try {
            log.debug("Getting access token...");
            accessToken = _oAuth2RestTemplate.getAccessToken();
            log.debug("Got access token!!! {}", accessToken);
        } catch (final OAuth2Exception e) {
            log.error("Could not obtain access token", e);
            throw new BadCredentialsException("Could not obtain access token", e);
        }

        final String providerId = (String) request.getSession().getAttribute("providerId");
        try {
            log.debug("Getting idToken...");
            final String idToken      = accessToken.getAdditionalInformation().get("id_token").toString();
            final Jwt    tokenDecoded = JwtHelper.decode(idToken);

            log.debug("===== : {}", tokenDecoded.getClaims());
            final Map<String, String> authInfo = _serializer.deserializeJsonToMapOfStrings(tokenDecoded.getClaims());

            final OpenIdConnectUserDetails user = new OpenIdConnectUserDetails(providerId, authInfo, accessToken, _plugin);

            if (shouldFilterEmailDomains() && !isAllowedEmailDomain(user.getEmail())) {
                log.error("Domain not allowed: {}", user.getEmail());
                throw new NewAutoAccountNotAutoEnabledException("New OpenID user, not on the domain whitelist.", user);
            }
            if (!_plugin.isEnabled(providerId)) {
                log.error("Provider {} is disabled, but user {} is trying to access it", providerId, user.getUsername());
                throw new NewAutoAccountNotAutoEnabledException("OpenID user is not on the enabled list.", user);
            }

            log.debug("Checking if user exists...");
            try {
                final UserI xdatUser = Users.getUser(user.getUsername());
                if (xdatUser.isEnabled()) {
                    log.debug("User is enabled...");
                    return new OpenIdAuthToken(xdatUser, "openid");
                } else {
                    throw (new NewAutoAccountNotAutoEnabledException("New OpenID user, needs to to be enabled.", xdatUser));
                }
            } catch (UserInitException e) {
                throw new BadCredentialsException("Cannot init OpenID user " + user.getUsername() + " from the database.", e);
            } catch (UserNotFoundException e) {
                final boolean userAutoEnabled  = Boolean.parseBoolean(_plugin.getProperty("auto.enabled", "false"));
                final boolean userAutoVerified = Boolean.parseBoolean(_plugin.getProperty("auto.verified", "false"));

                final UserI xdatUser = Users.createUser();
                xdatUser.setEmail(user.getEmail());
                xdatUser.setLogin(user.getUsername());
                xdatUser.setFirstname(user.getFirstname());
                xdatUser.setLastname(user.getLastname());
                xdatUser.setEnabled(userAutoEnabled);
                xdatUser.setVerified(userAutoVerified);

                if (Boolean.parseBoolean(_plugin.getProperty("forceUserCreate", "false"))) {
                    final EventDetails event = new EventDetails(EventUtils.CATEGORY.PROJECT_ACCESS, EventUtils.TYPE.PROCESS,"added new user", "new user logged in", "OpenID connect new user");
                    try {
                        Users.save(xdatUser, Users.getAdminUser(), true, event);
                        log.debug("User created, username: {}, ID: {}", xdatUser.getUsername(), xdatUser.getID());
                    } catch (Exception e1) {
                        log.error("An error occurred trying to save a new user:");
                    }
                }
                if (userAutoEnabled) {
                    return new OpenIdAuthToken(xdatUser, "openid");
                }
                throw new NewAutoAccountNotAutoEnabledException("New OpenID user, needs to to be enabled.", xdatUser);
            }
        } catch (final InvalidTokenException e) {
            throw new BadCredentialsException("Could not obtain user details from token", e);
        }
    }

    private boolean isAllowedEmailDomain(final String email) {
        return _allowedDomains.contains(StringUtils.removeAll(email, "^.*@").toLowerCase());
    }

    private boolean shouldFilterEmailDomains() {
        return Boolean.parseBoolean(_plugin.getProperty("shouldFilterEmailDomains"));
    }

    private static class NoopAuthenticationManager implements AuthenticationManager {

        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            throw new UnsupportedOperationException("No authentication should be done with this AuthenticationManager");
        }

    }


    private final OpenIdAuthPlugin  _plugin;
    private final SerializerService _serializer;
    private final List<String>      _allowedDomains;

    private OAuth2RestTemplate _oAuth2RestTemplate;
}