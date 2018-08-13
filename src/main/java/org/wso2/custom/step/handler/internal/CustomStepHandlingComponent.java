package org.wso2.custom.step.handler.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;

/**
 * @scr.component name="custom.step.handler"
 * immediate="true"
 */
public class CustomStepHandlingComponent {

    private static Log log = LogFactory.getLog(CustomStepHandlingComponent.class);

    protected void activate(ComponentContext ctxt) {

        try {
            log.info("Carbon Custom Claim Handler activated successfully.");
        } catch (Exception e) {
            log.error("Failed to activate Carbon Custom Claim Handler ", e);
        }
    }

    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.debug("Carbon Custom Claim Handler is deactivated ");
        }
    }

}