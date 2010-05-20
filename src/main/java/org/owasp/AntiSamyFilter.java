/**
 * Copyright to the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and limitations under the License.
 */

package org.owasp;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.owasp.validator.html.*;
import org.owasp.validator.html.scan.AntiSamyDOMScanner;

import javax.servlet.*;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.text.MessageFormat;
import java.util.List;


public class AntiSamyFilter implements Filter {
    private static final String NO_POLICY_FILE = "A policy file is required. Please set the init parameter ({0}) in your web.xml or call the setter";
    private static final String GENERIC_ERROR = "A problem occured while sanitizing the HTTP Response";
    private static final String POLICY_FILE_PARAM = "antisamy-policy-file";
    private static final String OUTPUT_ENCODING_PARAM = "antisamy-output-encoding";

    private static final String INPUT_ENCODING_PARAM = "antisamy-input-encoding";
    private Log log = LogFactory.getLog(AntiSamyFilter.class);
    private HttpResponseProxyFactory httpResponseProxyFactory;
    private HttpResponseInvocationHandlerFactory httpResponseInvocationHandlerFactory;
    private AntiSamy antiSamy;
    private PolicyFileLoader policyFileLoader;
    private String policyFile;
    private String inputEncoding = AntiSamyDOMScanner.DEFAULT_ENCODING_ALGORITHM;
    private String outputEncoding = AntiSamyDOMScanner.DEFAULT_ENCODING_ALGORITHM;

    public AntiSamyFilter() {
        httpResponseProxyFactory = new HttpResponseProxyFactory();
        httpResponseInvocationHandlerFactory = new HttpResponseInvocationHandlerFactory();
        antiSamy = new AntiSamy();
        policyFileLoader = new PolicyFileLoader();
    }

    public void init(FilterConfig filterConfig) throws ServletException {
        String policyFileLocation = filterConfig.getInitParameter(POLICY_FILE_PARAM);
        if (isBlank(policyFileLocation)) {
            throw new IllegalStateException(MessageFormat.format(NO_POLICY_FILE, POLICY_FILE_PARAM));
        }

        String output = filterConfig.getInitParameter(OUTPUT_ENCODING_PARAM);
        if (!isBlank(output)) {
            outputEncoding = output;
        }

        String input = filterConfig.getInitParameter(INPUT_ENCODING_PARAM);
        if (!isBlank(input)) {
            inputEncoding = input;
        }
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (response instanceof HttpServletResponse) {
            HttpServletResponseInvocationHandler invocationHandler = httpResponseInvocationHandlerFactory.build((HttpServletResponse) response);
            HttpServletResponse proxiedResponse = httpResponseProxyFactory.build(invocationHandler);
            chain.doFilter(request, proxiedResponse);

            try {
                Policy policy = policyFileLoader.load(policyFile);
                antiSamy.setInputEncoding(inputEncoding);
                antiSamy.setOutputEncoding(outputEncoding);
                CleanResults cleanResults = antiSamy.scan(invocationHandler.getContents(), policy);
                log.info("Number of Errors: " + cleanResults.getNumberOfErrors());
                if (log.isDebugEnabled()) {
                    log.debug("Errors found: ");
                    List errors = cleanResults.getErrorMessages();
                    for (int i = 0; i < errors.size(); i++) {
                        log.debug("\t" + (i + 1) + ". " + errors.get(i));
                    }
                }
                log.info("Scan time (in seconds): " + cleanResults.getScanTime());
                response.getOutputStream().write(cleanResults.getCleanHTML().getBytes());
            } catch (ScanException e) {
                log.error(GENERIC_ERROR, e);
            } catch (PolicyException e) {
                log.error(GENERIC_ERROR, e);
            }
        } else {
            chain.doFilter(request, response);
        }
    }

    public void destroy() {

    }

    private boolean isBlank(String value) {
        return value == null || value.trim().length() == 0;
    }

    protected void setHttpResponseProxyFactory(HttpResponseProxyFactory httpResponseProxyFactory) {
        this.httpResponseProxyFactory = httpResponseProxyFactory;
    }

    protected void setHttpResponseInvocationHandlerFactory(HttpResponseInvocationHandlerFactory httpResponseInvocationHandlerFactory) {
        this.httpResponseInvocationHandlerFactory = httpResponseInvocationHandlerFactory;
    }

    protected void setAntiSamy(AntiSamy antiSamy) {
        this.antiSamy = antiSamy;
    }

    protected void setLog(Log log) {
        this.log = log;
    }

    protected void setPolicyFileLoader(PolicyFileLoader policyFileLoader) {
        this.policyFileLoader = policyFileLoader;
    }

    public void setPolicyFile(String policyFile) {
        this.policyFile = policyFile;
    }

    public void setOutputEncoding(String outputEncoding) {
        this.outputEncoding = outputEncoding;
    }

    public void setInputEncoding(String inputEncoding) {
        this.inputEncoding = inputEncoding;
    }

    public String getInputEncoding() {
        return inputEncoding;
    }

    public String getOutputEncoding() {
        return outputEncoding;
    }
}
