package org.wso2.sample.authenticator.multi.attribute;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.security.AuthenticatorsConfiguration;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.sample.authenticator.multi.attribute.internal.MAAServiceComponent;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.wso2.sample.authenticator.multi.attribute.MultiAttributeAuthenticatorConstants.CLAIM_REGEX_PARAM_STARTS_WITH;
import static org.wso2.sample.authenticator.multi.attribute.MultiAttributeAuthenticatorConstants.CLAIM_URI_PARAM_STARTS_WITH;

public class MultiAttributeAuthenticatorUtil {

    private static final Log log = LogFactory.getLog(MultiAttributeAuthenticatorUtil.class);
    private static Map<String, String> claimRegexMap;

    public static String getUsernameFromIdentifier(String identifier, UserStoreManager userStoreManager)
            throws UserStoreException, AuthenticationFailedException {

        String identifierClaim = findIdentifier(identifier);
        if (identifierClaim == null) {
            if (log.isDebugEnabled()) {
                log.debug("Could not identify identifier type for " + identifier
                        + ". Hence using the entered value as the username");
            }
            return identifier;
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Found identifier type for " + identifier + ": " + identifierClaim);
            }
            return getUsernameFromClaim(identifierClaim, identifier, userStoreManager);
        }
    }


    private static String getUsernameFromClaim(String claimUri, String claimValue, UserStoreManager userStoreManager)
            throws UserStoreException, AuthenticationFailedException {

        String[] userList;
        String tenantDomain = MultitenantUtils.getTenantDomain(claimValue);
        String tenantAwareClaim = MultitenantUtils.getTenantAwareUsername(claimValue);

        if (log.isDebugEnabled()) {
            log.debug("Searching for a user with " + claimUri + ": " + tenantAwareClaim + " and tenant domain: "
                    + tenantDomain);
        }
        userList = userStoreManager.getUserList(claimUri, tenantAwareClaim,
                MultiAttributeAuthenticatorConstants.DEFAULT_PROFILE);

        if (userList == null || userList.length == 0) {
            String errorMessage = "No user found with the provided " + claimUri + ": " + claimValue;
            log.error(errorMessage);
            throw new AuthenticationFailedException(errorMessage);
        } else if (userList.length == 1) {
            if (log.isDebugEnabled()) {
                log.debug("Found single user " + userList[0] + " with the " + claimUri + ": " + claimValue);
            }
            return userList[0] + "@" + tenantDomain;
        }

        String errorMessage = "Multiple users found with the same claim("+ claimUri +") value " + claimValue + ": "
                + Arrays.toString(userList);
        log.error(errorMessage);
        throw new AuthenticationFailedException(errorMessage);
    }


    private static String findIdentifier(String identifier) {

        String tenantAwareIdentifier = MultitenantUtils.getTenantAwareUsername(identifier);
        Map<String, String> claimRegexMap = getClaimRegexMap();
        if (claimRegexMap.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("No claim regex patterns configured. Hence skipping the attribute based login");
            }
            return null;
        }

        for(Map.Entry<String, String> entry : claimRegexMap.entrySet()) {
            String claimUri = entry.getKey();
            String regex = entry.getValue();
            if (isRegexMatching(regex, tenantAwareIdentifier)){
                return claimUri;
            }
        }
        return null;
    }

    private static Map<String, String> getClaimRegexMap() {

        // keep in a static Map to avoid repeated generation of claimRegexMap
        if (claimRegexMap != null) {
            return claimRegexMap;
        }
        claimRegexMap = new HashMap<>();
        TreeMap<String, String> sortedConfig = new TreeMap<>();
        Map<String, String> authenticatorConfig = getAuthenticatorConfig().getParameterMap();

        // sort the propery names to keep the regex precedence
        sortedConfig.putAll(authenticatorConfig);
        for(Map.Entry<String, String> entry : sortedConfig.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();

            if (key.startsWith(CLAIM_URI_PARAM_STARTS_WITH)) {
                String claimName = key.replace(CLAIM_URI_PARAM_STARTS_WITH, "");
                if (authenticatorConfig.containsKey(CLAIM_REGEX_PARAM_STARTS_WITH + claimName)) {
                    String regex = authenticatorConfig.get(CLAIM_REGEX_PARAM_STARTS_WITH + claimName);
                    claimRegexMap.put(value, regex);
                }
            }
        }

        return claimRegexMap;
    }

    private static boolean isRegexMatching(String regularExpression, String attribute) {
        Pattern pattern = Pattern.compile(regularExpression);
        Matcher matcher = pattern.matcher(attribute);
        return matcher.matches();
    }

    private static AuthenticatorConfig getAuthenticatorConfig() {
        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance().getAuthenticatorBean(
                MultiAttributeAuthenticatorConstants.AUTHENTICATOR_NAME);
        if (authConfig == null) {
            authConfig = new AuthenticatorConfig();
            authConfig.setParameterMap(new HashMap<String, String>());
        }
        return authConfig;
    }


    // this method is an extra one for external components like recovery web app to find internal username
    public static String getUsernameFromIdentifier(String username)
            throws UserStoreException, AuthenticationFailedException {
        try {
            UserStoreManager userStoreManager;
            int tenantId = IdentityTenantUtil.getTenantIdOfUser(username);
            UserRealm userRealm = MAAServiceComponent.getRealmService().
                    getTenantUserRealm(tenantId);
            if (userRealm != null) {
                userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();
                return getUsernameFromIdentifier(username, userStoreManager);
            } else {
                throw new AuthenticationFailedException("Cannot find the user realm for the given tenant: " +
                        tenantId, User.getUserFromUserName(username));
            }
        } catch (IdentityRuntimeException e) {
            if (log.isDebugEnabled()) {
                log.debug("MultiAttributeAuthenticatorUtil failed while trying to get the tenant ID of the user " + username, e);
            }
            throw new AuthenticationFailedException(e.getMessage(), User.getUserFromUserName(username), e);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("MultiAttributeAuthenticatorUtil failed", e);
            }
            throw new AuthenticationFailedException(e.getMessage(), User.getUserFromUserName(username), e);
        }
    }


}
