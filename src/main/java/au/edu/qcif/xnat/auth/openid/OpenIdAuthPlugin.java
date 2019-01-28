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

import com.google.common.base.Function;
import com.google.common.base.Predicates;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringSubstitutor;
import org.nrg.framework.annotations.XnatPlugin;
import org.nrg.framework.services.SerializerService;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xnat.security.XnatSecurityExtension;
import org.nrg.xnat.security.provider.AuthenticationProviderConfigurationLocator;
import org.nrg.xnat.security.provider.ProviderAttributes;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.client.token.grant.redirect.AbstractRedirectResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;
import java.util.*;

/**
 * XNAT Authentication plugin.
 *
 * @author <a href='https://github.com/shilob'>Shilo Banihit</a>
 */
@XnatPlugin(value = "xnat-openid-auth-plugin", name = "XNAT OpenID Authentication Provider Plugin")
@EnableOAuth2Client
@Component
@Slf4j
public class OpenIdAuthPlugin implements XnatSecurityExtension {
    public static final String OPENID_LOGIN_HANDLER = "/openid-login";

    @Autowired
    public OpenIdAuthPlugin(final AuthenticationProviderConfigurationLocator locator, final SiteConfigPreferences preferences, final SerializerService serializer) {
        _openIdUri = preferences.getSiteUrl() + OPENID_LOGIN_HANDLER;
        _serializer = serializer;

        _providerProperties = loadProviderProperties(locator);
        _providerDetails = Maps.transformValues(_providerProperties, new Function<Properties, OAuth2ProtectedResourceDetails>() {
            @Override
            public OAuth2ProtectedResourceDetails apply(final Properties properties) {
                return buildProtectedResourceDetails(properties);
            }
        });
        _enabledOpenIdProviders = new ArrayList<>(Sets.intersection(_providerProperties.keySet(), new HashSet<>(preferences.getEnabledProviders())));

        LOGIN_DISPLAY = _enabledOpenIdProviders.isEmpty() ? "" : StringUtils.join(Iterables.filter(Lists.transform(_enabledOpenIdProviders, new Function<String, String>() {
            @Nullable
            @Override
            public String apply(final String providerId) {
                final String link = getProviderProperty(providerId, "link");
                final Map<String, String> variables = new HashMap<>();
                variables.put("providerId", providerId);
                return StringSubstitutor.replace(link, variables);
            }
        }), Predicates.<String>notNull()), "\n");
        CREDENTIALS_BOX_STYLE = _enabledOpenIdProviders.isEmpty() ? "" : Iterables.any(Lists.transform(_enabledOpenIdProviders, new Function<String, Boolean>() {
            @Override
            public Boolean apply(final String providerId) {
                return Boolean.parseBoolean(getProviderProperty(providerId, "disableUsernamePasswordLogin", "false"));
            }
        }), Predicates.equalTo(false)) ? "" : "display:none";
    }

    @SuppressWarnings("unused")
    public static String getLoginDisplay() {
        return LOGIN_DISPLAY;
    }

    @SuppressWarnings("unused")
    public static String getUsernamePasswordStyle() {
        return CREDENTIALS_BOX_STYLE;
    }

    @Override
    public String getAuthMethod() {
        return PROVIDER_ID;
    }

    @Override
    public void configure(final HttpSecurity http) {
        log.debug("Configuring HTTP security for the OpenID plugin: adding OAuth2ClientContextFilter and OpenIdConnectFilter");
        http.addFilterAfter(new OAuth2ClientContextFilter(), AbstractPreAuthenticatedProcessingFilter.class)
            .addFilterAfter(openIdConnectFilter(), OAuth2ClientContextFilter.class);
    }

    @Override
    public void configure(final AuthenticationManagerBuilder builder) {
        log.debug("Configuring authentication manager for the OpenID plugin: no op");
    }

    @Bean
    @Scope("prototype")
    public OpenIdConnectFilter openIdConnectFilter() {
        log.info("Now creating openIdConnectFilter");
        return new OpenIdConnectFilter(this, _serializer);
    }

    @Bean
    @Scope(value = WebApplicationContext.SCOPE_SESSION, proxyMode = ScopedProxyMode.TARGET_CLASS)
    public OAuth2RestTemplate oAuth2RestTemplate(final OAuth2ClientContext clientContext) {
        log.debug("Creating new REST template instance for request {}", clientContext.getAccessTokenRequest());
        final HttpServletRequest request    = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        final String             providerId = request.getParameter("providerId");

        log.debug("Provider ID is: {}", providerId);
        request.getSession().setAttribute("providerId", providerId);
        return new OAuth2RestTemplate(getProtectedResourceDetails(providerId), clientContext);
    }

    @Nonnull
    public List<String> getEnabledOpenIdProviders() {
        return _enabledOpenIdProviders;
    }

    public boolean isEnabled(final String providerId) {
        return _enabledOpenIdProviders.contains(providerId);
    }

    public String getOpenIdUri() {
        return _openIdUri;
    }

    @Nullable
    public String getProviderProperty(final String providerId, final String property) {
        return getProviderProperty(providerId, property, null);
    }

    @Nullable
    public String getProviderProperty(final @Nonnull String providerId, final @Nonnull String property, final @Nullable String defaultValue) {
        return _providerProperties.containsKey(providerId) ? _providerProperties.get(providerId).getProperty(property, defaultValue) : null;
    }

    @Nonnull
    private OAuth2ProtectedResourceDetails getProtectedResourceDetails(final @Nonnull String providerId) {
        if (!_providerDetails.containsKey(providerId)) {
            throw new IllegalArgumentException("There is no provider definition for the ID '" + providerId + "'");
        }
        return _providerDetails.get(providerId);
    }

    @Nonnull
    private OAuth2ProtectedResourceDetails buildProtectedResourceDetails(final @Nonnull Properties properties) {
        final String grantType = properties.getProperty("grantType", "authorization_code");

        final String   providerId        = properties.getProperty(ProviderAttributes.PROVIDER_ID);
        final String   clientId          = properties.getProperty("clientId");
        final String   clientSecret      = properties.getProperty("clientSecret");
        final String   accessTokenUri    = properties.getProperty("accessTokenUri");
        final String   userAuthUri       = properties.getProperty("userAuthUri");
        final String   tokenName         = properties.getProperty("tokenName");
        final String   preEstablishedUri = getOpenIdUri();
        final String[] scopes            = properties.getProperty("scopes").split(",");

        log.debug("Creating protected resource details of provider: {}\nid: {}\nclientId: {}\nclientSecret: {}\naccessTokenUri: {}\nuserAuthUri: {}\ntokenName: {}\npreEstablishedUri: {}\nscopes: {}", providerId, clientId, clientSecret, accessTokenUri, userAuthUri, tokenName, preEstablishedUri, scopes);

        final BaseOAuth2ProtectedResourceDetails details = getResourceDetailsByGrantType(providerId, grantType);
        details.setId(providerId);
        details.setClientId(clientId);
        details.setClientSecret(clientSecret);
        details.setAccessTokenUri(accessTokenUri);
        details.setTokenName(tokenName);
        details.setScope(Arrays.asList(scopes));

        if (AbstractRedirectResourceDetails.class.isAssignableFrom(details.getClass())) {
            final AbstractRedirectResourceDetails redirect = (AbstractRedirectResourceDetails) details;
            redirect.setUserAuthorizationUri(userAuthUri);
            redirect.setPreEstablishedRedirectUri(preEstablishedUri);
            redirect.setUseCurrentUri(false);
        } else if (details instanceof ResourceOwnerPasswordResourceDetails) {
            final ResourceOwnerPasswordResourceDetails password = (ResourceOwnerPasswordResourceDetails) details;
            password.setUsername(properties.getProperty("username"));
            password.setPassword(properties.getProperty("password"));
        }

        return details;
    }

    @Nonnull
    private static BaseOAuth2ProtectedResourceDetails getResourceDetailsByGrantType(final @Nonnull String providerId, final @Nonnull String grantType) {
        switch (grantType) {
            case "implicit":
                log.debug("Creating OAuth2ProtectedResourceDetails instance as ImplicitResourceDetails for provider ID {}", providerId);
                return new ImplicitResourceDetails();

            case "client_credentials":
                log.debug("Creating OAuth2ProtectedResourceDetails instance as ClientCredentialsResourceDetails for provider ID {}", providerId);
                return new ClientCredentialsResourceDetails();

            case "authorization_code":
                log.debug("Creating OAuth2ProtectedResourceDetails instance as AuthorizationCodeResourceDetails for provider ID {}", providerId);
                return new AuthorizationCodeResourceDetails();

            case "password":
                log.debug("Creating OAuth2ProtectedResourceDetails instance as ResourceOwnerPasswordResourceDetails for provider ID {}", providerId);
                return new ResourceOwnerPasswordResourceDetails();

            default:
                throw new RuntimeException("Unknown grant type '" + grantType + "' for provider ID '" + providerId + "'");
        }
    }

    private Map<String, Properties> loadProviderProperties(final AuthenticationProviderConfigurationLocator locator) {
        final Map<String, ProviderAttributes> openIdProviders = locator.getProviderDefinitionsByAuthMethod("openid");
        if (openIdProviders.isEmpty()) {
            throw new RuntimeException("You must configure an OpenID provider");
        }
        log.info("Found {} OpenID provider definitions: {}", openIdProviders.size(), StringUtils.join(openIdProviders.keySet(), ", "));
        return Maps.transformValues(openIdProviders, new Function<ProviderAttributes, Properties>() {
            @Override
            public Properties apply(final ProviderAttributes attributes) {
                final Properties properties = attributes.getProperties();
                properties.setProperty(ProviderAttributes.PROVIDER_ID, attributes.getProviderId());
                properties.setProperty(ProviderAttributes.PROVIDER_NAME, attributes.getName());
                return properties;
            }
        });
    }

    private static final String      PROVIDER_ID         = "openid";

    private static String LOGIN_DISPLAY;
    private static String CREDENTIALS_BOX_STYLE;

    private final Map<String, Properties>                     _providerProperties;
    private final Map<String, OAuth2ProtectedResourceDetails> _providerDetails;
    private final List<String>                                _enabledOpenIdProviders;
    private final String                                      _openIdUri;
    private final SerializerService                           _serializer;
}
