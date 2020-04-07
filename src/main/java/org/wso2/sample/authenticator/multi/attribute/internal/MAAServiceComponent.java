package org.wso2.sample.authenticator.multi.attribute.internal;

import org.wso2.sample.authenticator.multi.attribute.MultiAttributeAuthenticator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.user.core.service.RealmService;


/**
 * @scr.component name="org.wso2.sample.authenticator.multi.attribute.component" immediate="true"
 * @scr.reference name="realm.service"
 * interface="org.wso2.carbon.user.core.service.RealmService"cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 */
public class MAAServiceComponent {

    private static Log log = LogFactory.getLog(MAAServiceComponent.class);

    private static RealmService realmService;

    public static RealmService getRealmService() {
        return realmService;
    }

    protected void setRealmService(RealmService realmService) {
        log.debug("Setting the Realm Service");
        MAAServiceComponent.realmService = realmService;
    }

    protected void activate(ComponentContext ctxt) {
        try {
            MultiAttributeAuthenticator basicAuth = new MultiAttributeAuthenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), basicAuth, null);
            if (log.isDebugEnabled()) {
                log.info("AttributeBasedAuthenticator bundle is activated");
            }
        } catch (Throwable e) {
            log.error("AttributeBasedAuthenticator bundle activation Failed", e);
        }
    }

    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.info("AttributeBasedAuthenticator bundle is deactivated");
        }
    }

    protected void unsetRealmService(RealmService realmService) {
        log.debug("UnSetting the Realm Service");
        MAAServiceComponent.realmService = null;
    }

}
