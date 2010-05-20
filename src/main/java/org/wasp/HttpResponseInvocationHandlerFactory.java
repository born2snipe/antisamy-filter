package org.wasp;

import javax.servlet.http.HttpServletResponse;

public class HttpResponseInvocationHandlerFactory {
    public HttpServletResponseInvocationHandler build(HttpServletResponse response) {
        return new HttpServletResponseInvocationHandler(response);
    }
}
