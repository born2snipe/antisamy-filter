package org.wasp;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.CleanResults;
import org.owasp.validator.html.PolicyException;
import org.owasp.validator.html.ScanException;

import javax.servlet.*;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;


public class AntiSamyFilter implements Filter {
    private static final String ERROR = "A problem occured while sanitizing the HTTP Response";
    private Log log = LogFactory.getLog(AntiSamyFilter.class);
    private HttpResponseProxyFactory httpResponseProxyFactory;
    private HttpResponseInvocationHandlerFactory httpResponseInvocationHandlerFactory;
    private AntiSamy antiSamy;

    public AntiSamyFilter() {
        httpResponseProxyFactory = new HttpResponseProxyFactory();
        httpResponseInvocationHandlerFactory = new HttpResponseInvocationHandlerFactory();
        antiSamy = new AntiSamy();
    }

    public void init(FilterConfig filterConfig) throws ServletException {

    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (response instanceof HttpServletResponse) {
            HttpServletResponseInvocationHandler invocationHandler = httpResponseInvocationHandlerFactory.build();
            HttpServletResponse proxiedResponse = httpResponseProxyFactory.build((HttpServletResponse) response, invocationHandler);
            chain.doFilter(request, proxiedResponse);

            try {
                CleanResults cleanResults = antiSamy.scan(invocationHandler.getContents());
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
                log.error(ERROR, e);
            } catch (PolicyException e) {
                log.error(ERROR, e);
            }
        } else {
            chain.doFilter(request, response);
        }
    }

    public void destroy() {

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
}
