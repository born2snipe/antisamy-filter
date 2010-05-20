package org.wasp;

import org.apache.commons.logging.Log;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InOrder;
import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.CleanResults;
import org.owasp.validator.html.PolicyException;
import org.owasp.validator.html.ScanException;

import javax.servlet.FilterChain;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import static junit.framework.Assert.assertEquals;
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

        when(antiSamy.scan(TAINTED_HTML)).thenThrow(error);

        filter.doFilter(request, response, filterChain);

        verify(log).error("A problem occured while sanitizing the HTTP Response", error);
    }

    @Test
    public void test_doFilter_antiSamy_ThrowsPolicyException() throws Exception {
        PolicyException error = new PolicyException("");

        when(antiSamy.scan(TAINTED_HTML)).thenThrow(error);

        filter.doFilter(request, response, filterChain);

        verify(log).error("A problem occured while sanitizing the HTTP Response", error);
    }

    @Test
    public void test_doFilter() throws Exception {
        InOrder inOrder = inOrder(filterChain, antiSamy);

        when(antiSamy.scan(TAINTED_HTML)).thenReturn(cleanResults);

        filter.doFilter(request, response, filterChain);

        inOrder.verify(filterChain).doFilter(request, proxyResponse);
        inOrder.verify(antiSamy).scan(TAINTED_HTML);
        assertEquals(CLEANED_HTML, new String(outputStream.output.toByteArray()));
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

        filter = new AntiSamyFilter();
        filter.setAntiSamy(antiSamy);
        filter.setHttpResponseInvocationHandlerFactory(httpResponseInvocationHandlerFactory);
        filter.setHttpResponseProxyFactory(httpResponseProxyFactory);
        filter.setLog(log);

        when(httpResponseInvocationHandlerFactory.build(response)).thenReturn(invocationHandler);
        when(httpResponseProxyFactory.build(invocationHandler)).thenReturn(proxyResponse);
        when(invocationHandler.getContents()).thenReturn(TAINTED_HTML);
        when(response.getOutputStream()).thenReturn(outputStream);
        when(cleanResults.getCleanHTML()).thenReturn(CLEANED_HTML);
    }

    private static class StubOutputStream extends ServletOutputStream {
        private ByteArrayOutputStream output = new ByteArrayOutputStream();

        @Override
        public void write(int b) throws IOException {
            output.write(b);
        }
    }
}
