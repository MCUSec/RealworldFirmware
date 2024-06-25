package iotscope.utility;

public class UrlInfo {
    private final String protocol;
    private final String domain;
    private final String port;
    private final String path;

    /**
     * URL wrapper object
     * @param protocol of the url
     * @param domain of the url
     * @param port contained in the url
     * @param path of the url
     */
    public UrlInfo(String protocol, String domain, String port, String path) {
        this.protocol = protocol;
        this.domain = domain;
        this.port = port;
        this.path = path;
    }


    public String getProtocol() {
        return protocol;
    }


    public String getDomain() {
        return domain;
    }


    public String getPort() {
        return port;
    }


    public String getPath() {
        return path;
    }


    @Override
    public String toString() {
        return "UrlInfo{" +
                "protocol='" + protocol + '\'' +
                ", domain='" + domain + '\'' +
                ", port='" + port + '\'' +
                ", path='" + path + '\'' +
                '}';
    }
}
