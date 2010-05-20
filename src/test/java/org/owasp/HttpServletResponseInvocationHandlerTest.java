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
