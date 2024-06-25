package iotscope.utility.unknownScheme;

import java.net.URLStreamHandler;
import java.net.URLStreamHandlerFactory;

/**
 * Custom URL handler to add unknown as URL protocol without running in any exceptions
 */
public class CustomURLStreamHandlerFactory   implements URLStreamHandlerFactory {
    @Override
    public URLStreamHandler createURLStreamHandler(String protocol) {
        if ("unknown".equals(protocol)) {
            return new CustomURLStreamHandler();
        }

        return null;
    }

}
