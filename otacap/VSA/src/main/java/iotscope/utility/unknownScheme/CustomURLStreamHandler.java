package iotscope.utility.unknownScheme;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
/**
 * Custom URL handler to add unknown as URL protocol without running in any exceptions
 */
public class CustomURLStreamHandler extends URLStreamHandler {

    @Override
    protected URLConnection openConnection(URL url) throws IOException {
        return new CustomURLConnection(url);
    }

}
