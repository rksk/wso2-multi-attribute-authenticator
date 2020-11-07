package org.wso2.sample.authenticator.multi.attribute;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticator;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.sample.authenticator.multi.attribute.internal.MAAServiceComponent;

import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Custom Basic Authenticator for multi-attribute authentication.
 */
public class MultiAttributeAuthenticator extends BasicAuthenticator {

    private static final Log log = LogFactory.getLog(MultiAttributeAuthenticator.class);

    private static final String PASSWORD_PROPERTY = "PASSWORD_PROPERTY";
    private static final String RE_CAPTCHA_USER_DOMAIN = "user-domain-recaptcha";

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        boolean isAuthenticated;
        UserStoreManager userStoreManager;
        String internalUsername;

        String username = request.getParameter(BasicAuthenticatorConstants.USER_NAME);
        String password = request.getParameter(BasicAuthenticatorConstants.PASSWORD);

        Map<String, Object> authProperties = context.getProperties();
        if (authProperties == null) {
            authProperties = new HashMap<String, Object>();
            context.setProperties(authProperties);
        }

        authProperties.put(PASSWORD_PROPERTY, password);

        // Reset RE_CAPTCHA_USER_DOMAIN thread local variable before the authentication
        IdentityUtil.threadLocalProperties.get().remove(RE_CAPTCHA_USER_DOMAIN);
        // Check the authentication
        try {
            int tenantId = IdentityTenantUtil.getTenantIdOfUser(username);
            UserRealm userRealm = MAAServiceComponent.getRealmService().
                    getTenantUserRealm(tenantId);
            if (userRealm != null) {
                userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();

                internalUsername = MultiAttributeAuthenticatorUtil.getUsernameFromIdentifier(username,
                        userStoreManager);
                isAuthenticated = userStoreManager.
                        authenticate(MultitenantUtils.getTenantAwareUsername(internalUsername), password);
            } else {
                throw new AuthenticationFailedException("Cannot find the user realm for the given tenant: " +
                        tenantId, User.getUserFromUserName(username));
            }
        } catch (IdentityRuntimeException e) {
            if (log.isDebugEnabled()) {
                log.debug("BasicAuthentication failed while trying to get the tenant ID of the user " + username, e);
            }
            throw new AuthenticationFailedException(e.getMessage(), User.getUserFromUserName(username), e);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("BasicAuthentication failed while trying to authenticate", e);
            }
            throw new AuthenticationFailedException(e.getMessage(), User.getUserFromUserName(username), e);
        }

        if (!isAuthenticated) {
            if (log.isDebugEnabled()) {
                log.debug("User authentication failed due to invalid credentials");
            }
            if (IdentityUtil.threadLocalProperties.get().get(RE_CAPTCHA_USER_DOMAIN) != null) {
                internalUsername = IdentityUtil.addDomainToName(internalUsername,
                        IdentityUtil.threadLocalProperties.get().get(RE_CAPTCHA_USER_DOMAIN).toString());
            }
            IdentityUtil.threadLocalProperties.get().remove(RE_CAPTCHA_USER_DOMAIN);
            throw new InvalidCredentialsException("User authentication failed due to invalid credentials",
                    User.getUserFromUserName(internalUsername));
        }

        String tenantDomain = MultitenantUtils.getTenantDomain(internalUsername);
        authProperties.put("user-tenant-domain", tenantDomain);

        internalUsername = FrameworkUtils.prependUserStoreDomainToName(internalUsername);

        context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(internalUsername));

        String rememberMe = request.getParameter("chkRemember");
        if ("on".equals(rememberMe)) {
            context.setRememberMe(true);
        }
    }

    @Override
    public String getFriendlyName() {
        return MultiAttributeAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {
        return MultiAttributeAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

}
