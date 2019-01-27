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

import java.util.Map;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.apache.commons.lang3.StringUtils;
import org.nrg.xdat.security.XDATUser;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * OIDC user details
 * 
 * @author <a href='https://github.com/shilob'>Shilo Banihit</a>
 * 
 */
@Getter
@Setter
@Accessors(prefix = "_")
public class OpenIdConnectUserDetails extends XDATUser {
	public OpenIdConnectUserDetails(final String providerId, final OpenIdAuthPlugin plugin, Map<String, String> userInfo, final OAuth2AccessToken accessToken) {
		setUsername(providerId + "_" + userInfo.get("sub"));
		setFirstname(getUserInfo(plugin, providerId, userInfo, "givenNameProperty"));
		setLastname(getUserInfo(plugin, providerId, userInfo, "familyNameProperty"));
		setName(userInfo.get("name"));
		setEmail(getUserInfo(plugin, providerId, userInfo, "emailProperty"));
		setPicture(userInfo.get("picture"));
		setAccessToken(accessToken);
	}

	private static String getUserInfo(final OpenIdAuthPlugin plugin, final String providerId, final Map<String, String> userInfo, final String property) {
		return StringUtils.defaultIfBlank(userInfo.get(plugin.getProviderProperty(providerId, property, "")), "");
	}

	private String            _username;
	private String            _firstName;
	private String            _lastName;
	private String            _name;
	private String            _email;
	private String            _picture;
	private OAuth2AccessToken _accessToken;
}
