package org.wasp;

import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Proxy;


public class HttpResponseProxyFactory {
    public HttpServletResponse build(HttpServletResponseInvocationHandler invocationHandler) {
        return (HttpServletResponse) Proxy.newProxyInstance(
                Thread.currentThread().getContextClassLoader(),
                new Class[]{HttpServletResponse.class},
                invocationHandler
        );
    }
}
