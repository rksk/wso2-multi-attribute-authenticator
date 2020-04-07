package org.wso2.sample.authenticator.multi.attribute;

/**
 * Constants used by the MultiAttributeAuthenticator
 */
public class MultiAttributeAuthenticatorConstants {

    public static final String AUTHENTICATOR_NAME = "MultiAttributeAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "multi-attribute-authenticator";

    public static final String DEFAULT_PROFILE = "default";
    public static final String TENANT_DOMAIN = "tenantDomain";

    public static final String CLAIM_URI_PARAM_STARTS_WITH = "claimuri_";
    public static final String CLAIM_REGEX_PARAM_STARTS_WITH = "claimregex_";

    public static final String EMAIL_CLAIM = "http://wso2.org/claims/emailaddress";

    // Regex based identifier selection
    public static final String USERNAME_CLAIM = "http://wso2.org/claims/username";
    public static final String EMAIL_REGEX = "^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,4}$";

    public static final String MOBILE_CLAIM = "http://wso2.org/claims/mobile";
    public static final String MOBILE_REGEX = "^\\+?(\\d{3})*[0-9,\\-]{8,}$";

}
