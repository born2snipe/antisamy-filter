package org.wasp;

import org.junit.Before;
import org.junit.Test;

import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.lang.reflect.Method;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;
import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.*;

public class HttpServletResponseInvocationHandlerTest {
    private HttpServletResponse response;
    private HttpServletResponseInvocationHandler handler;

    @Test
    public void test_callDelegate() throws Throwable {
        when(response.getCharacterEncoding()).thenReturn("encoding");

        assertEquals("encoding", handler.invoke(null, method("getCharacterEncoding"), new Object[0]));
        verify(response).getCharacterEncoding();
    }

    @Test
    public void test_getWriter() throws Throwable {
        Object result = handler.invoke(null, method("getWriter"), new Object[0]);

        assertTrue(result instanceof PrintWriter);
        PrintWriter writer = (PrintWriter) result;
        writer.println("test");

        assertEquals("test", handler.getContents());
        verifyZeroInteractions(response);
    }

    @Test
    public void test_getOutputStream() throws Throwable {
        Object result = handler.invoke(null, method("getOutputStream"), new Object[0]);

        verifyZeroInteractions(response);
        assertSame(handler.output, result);
    }

    private Method method(String name) {
        for (Method method : HttpServletResponse.class.getMethods()) {
            if (method.getName().equals(name)) {
                return method;
            }
        }
        throw new RuntimeException("could not find method");
    }

    @Before
    public void setUp() throws Exception {
        response = mock(HttpServletResponse.class);
        handler = new HttpServletResponseInvocationHandler(response);
    }
}
