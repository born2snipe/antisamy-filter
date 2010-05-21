/**
 * Copyright to the original author or authors.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 *     * The names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.owasp;

import org.apache.commons.logging.Log;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InOrder;
import org.owasp.validator.html.*;
import org.owasp.validator.html.scan.AntiSamyDOMScanner;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.fail;
import static org.mockito.Mockito.*;

public class AntiSamyFilterTest {
    private static final String CLEANED_HTML = "cleaned-html";
    private static final String TAINTED_HTML = "tainted-html";

    private HttpServletRequest request;
    private AntiSamyFilter filter;
    private HttpServletResponse response;
    private FilterChain filterChain;
    private HttpResponseProxyFactory httpResponseProxyFactory;
    private HttpServletResponse proxyResponse;
    private HttpResponseInvocationHandlerFactory httpResponseInvocationHandlerFactory;
    private HttpServletResponseInvocationHandler invocationHandler;
    private AntiSamy antiSamy;
    private CleanResults cleanResults;
    private StubOutputStream outputStream;
    private Log log;
    private FilterConfig filterConfig;
    private PolicyFileLoader policyFileLoader;
    private Policy policy;
    private static final String POLICY_FILE = "policyFile";

    @Test
    public void test_init_policyParamIsEmptyString() throws ServletException {
        when(filterConfig.getInitParameter("antisamy-policy-file")).thenReturn("");
        try {
            filter.init(filterConfig);
            fail();
        } catch (IllegalStateException err) {
            assertEquals("A policy file is required. Please set the init parameter (antisamy-policy-file) in your web.xml or call the setter", err.getMessage());
        }
    }

    @Test
    public void test_init_paramIsNull() throws ServletException {
        when(filterConfig.getInitParameter("antisamy-policy-file")).thenReturn(null);

        try {
            filter.init(filterConfig);
            fail();
        } catch (IllegalStateException err) {
            assertEquals("A policy file is required. Please set the init parameter (antisamy-policy-file) in your web.xml or call the setter", err.getMessage());
        }
    }

    @Test
    public void test_init() throws ServletException {
        filter.setPolicyFile(null);

        when(filterConfig.getInitParameter("antisamy-policy-file")).thenReturn(POLICY_FILE);

        filter.init(filterConfig);

        assertEquals("UTF-8", filter.getOutputEncoding());
        assertEquals("UTF-8", filter.getInputEncoding());
        assertEquals(POLICY_FILE, filter.getPolicyFile());
    }

    @Test
    public void test_init_specificOutputEncoding() throws ServletException {
        when(filterConfig.getInitParameter("antisamy-policy-file")).thenReturn(POLICY_FILE);
        when(filterConfig.getInitParameter("antisamy-output-encoding")).thenReturn("output");

        filter.init(filterConfig);

        assertEquals("output", filter.getOutputEncoding());
    }

    @Test
    public void test_init_specificInputEncoding() throws ServletException {
        when(filterConfig.getInitParameter("antisamy-policy-file")).thenReturn(POLICY_FILE);
        when(filterConfig.getInitParameter("antisamy-input-encoding")).thenReturn("input");

        filter.init(filterConfig);

        assertEquals("input", filter.getInputEncoding());
    }

    @Test
    public void test_doFilter_NotHtml() throws Exception {
        when(invocationHandler.getBytes()).thenReturn(new String("test").getBytes());
        when(proxyResponse.getContentType()).thenReturn("application/pdf");

        filter.doFilter(request, response, filterChain);

        verifyZeroInteractions(antiSamy);
        assertEquals("test", new String(outputStream.output.toByteArray()));
    }

    @Test
    public void test_doFilter_NonHttpRequest() throws Exception {
        ServletResponse response = mock(ServletResponse.class);

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoMoreInteractions(antiSamy, httpResponseInvocationHandlerFactory, httpResponseProxyFactory);
    }

    @Test
    public void test_doFilter_antiSamy_ThrowsScanException() throws Exception {
        ScanException error = new ScanException("");

        when(antiSamy.scan(TAINTED_HTML, policy)).thenThrow(error);

        filter.doFilter(request, response, filterChain);

        verify(log).error("A problem occured while sanitizing the HTTP Response", error);
    }

    @Test
    public void test_doFilter_antiSamy_ThrowsPolicyException() throws Exception {
        PolicyException error = new PolicyException("");

        when(antiSamy.scan(TAINTED_HTML, policy)).thenThrow(error);

        filter.doFilter(request, response, filterChain);

        verify(log).error("A problem occured while sanitizing the HTTP Response", error);
    }

    @Test
    public void test_doFilter() throws Exception {
        InOrder inOrder = inOrder(filterChain, antiSamy);

        filter.doFilter(request, response, filterChain);

        inOrder.verify(filterChain).doFilter(request, proxyResponse);
        inOrder.verify(antiSamy).setInputEncoding(AntiSamyDOMScanner.DEFAULT_ENCODING_ALGORITHM);
        inOrder.verify(antiSamy).setOutputEncoding(AntiSamyDOMScanner.DEFAULT_ENCODING_ALGORITHM);
        inOrder.verify(antiSamy).scan(TAINTED_HTML, policy);
        assertEquals(CLEANED_HTML, new String(outputStream.output.toByteArray()));
    }

    @Test
    public void test_doFilter_specificOutputEncoding() throws Exception {
        InOrder inOrder = inOrder(antiSamy);

        filter.setOutputEncoding("output");

        filter.doFilter(request, response, filterChain);

        inOrder.verify(antiSamy).setInputEncoding(AntiSamyDOMScanner.DEFAULT_ENCODING_ALGORITHM);
        inOrder.verify(antiSamy).setOutputEncoding("output");
        inOrder.verify(antiSamy).scan(TAINTED_HTML, policy);
    }

    @Test
    public void test_doFilter_specificInputEncoding() throws Exception {
        InOrder inOrder = inOrder(antiSamy);

        filter.setInputEncoding("input");

        filter.doFilter(request, response, filterChain);

        inOrder.verify(antiSamy).setInputEncoding("input");
        inOrder.verify(antiSamy).setOutputEncoding(AntiSamyDOMScanner.DEFAULT_ENCODING_ALGORITHM);
        inOrder.verify(antiSamy).scan(TAINTED_HTML, policy);
    }

    @Before
    public void setUp() throws Exception {
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        filterChain = mock(FilterChain.class);
        proxyResponse = mock(HttpServletResponse.class);
        httpResponseProxyFactory = mock(HttpResponseProxyFactory.class);
        httpResponseInvocationHandlerFactory = mock(HttpResponseInvocationHandlerFactory.class);
        invocationHandler = mock(HttpServletResponseInvocationHandler.class);
        antiSamy = mock(AntiSamy.class);
        cleanResults = mock(CleanResults.class);
        outputStream = new StubOutputStream();
        log = mock(Log.class);
        policyFileLoader = mock(PolicyFileLoader.class);
        policy = mock(Policy.class);
        filterConfig = mock(FilterConfig.class);

        filter = new AntiSamyFilter();
        filter.setAntiSamy(antiSamy);
        filter.setHttpResponseInvocationHandlerFactory(httpResponseInvocationHandlerFactory);
        filter.setHttpResponseProxyFactory(httpResponseProxyFactory);
        filter.setLog(log);
        filter.setPolicyFileLoader(policyFileLoader);
        filter.setPolicyFile(POLICY_FILE);

        when(httpResponseInvocationHandlerFactory.build(response)).thenReturn(invocationHandler);
        when(httpResponseProxyFactory.build(invocationHandler)).thenReturn(proxyResponse);
        when(invocationHandler.getContents()).thenReturn(TAINTED_HTML);
        when(response.getOutputStream()).thenReturn(outputStream);
        when(cleanResults.getCleanHTML()).thenReturn(CLEANED_HTML);
        when(policyFileLoader.load(POLICY_FILE)).thenReturn(policy);
        when(antiSamy.scan(TAINTED_HTML, policy)).thenReturn(cleanResults);
        when(proxyResponse.getContentType()).thenReturn("text/html");
    }

    private static class StubOutputStream extends ServletOutputStream {
        private ByteArrayOutputStream output = new ByteArrayOutputStream();

        @Override
        public void write(int b) throws IOException {
            output.write(b);
        }
    }
}
