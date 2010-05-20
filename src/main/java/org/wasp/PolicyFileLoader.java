package org.wasp;

import org.owasp.validator.html.Policy;
import org.owasp.validator.html.PolicyException;

import java.io.File;


public class PolicyFileLoader {
    public Policy load(String fileLocation) {
        try {
            return Policy.getInstance(new File(fileLocation));
        } catch (PolicyException e) {
            throw new RuntimeException(e);
        }
    }
}
