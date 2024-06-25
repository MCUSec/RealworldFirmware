package iotscope.utility;

import iotscope.backwardslicing.BackwardContext;
import iotscope.base.StmtPoint;
import iotscope.graph.SValuePoint;
import iotscope.graph.ValuePoint;
import iotscope.main.Main;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Unit;
import soot.jimple.Stmt;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Flags results in case we find signs for transformation
 */
public class CommunicationDetection {

    private static final Logger LOGGER = LoggerFactory.getLogger(Main.class);

    //later for whois queries org.apache.commons.net.whois
    private static final Pattern regex = Pattern.compile("(^(.*:?\\/?\\/?)?192\\.168\\.\\d\\d?\\d?\\.\\d\\d?\\d?.*)|(^(.*:?\\/?\\/?)10\\.\\d\\d?\\d?\\.\\d\\d?\\d?\\.\\d\\d?\\d?.*)|(^(.*:?\\/?\\/?)172\\.1[6-9]\\.\\d\\d?\\d?\\.\\d\\d?\\d?.*)|(^(.*:?\\/?\\/?)172\\.2[0-9]\\.\\d\\d?\\d?\\.\\d\\d?\\d?.*)|(^(.*:?\\/?\\/?)172\\.3[0-1]\\.\\d\\d?\\d?\\.\\d\\d?\\d?.*)|(^(.*:?\\/?\\/?)[fF][cCdD].*)|^(.*\\.local.*)");
    private static final Pattern regexFindUIInput = Pattern.compile("<android\\.widget.*:.*getText\\(\\)>");
    private static final Pattern regexFindEncryption = Pattern.compile("(.*[cC]rypt.*)"); //(.*[bB]ouncycastle.*)| -> pem object -> false positive
    private static final Pattern regexFindEncoding = Pattern.compile("(.*[eE]ncod.*)|(.*[bB]ase64.*)|(.*[bB]64.*)");
    private static final Pattern regexFindObfuscation = Pattern.compile("(.*<<.*)|(.*<<<.*)|(.*>>.*)|(.*>>>.*)|(.*&.*)|(.*\\|.*)|(.*\\^.*)");
    private static final Pattern regexFindUPnP = Pattern.compile("(.*[Uu][Pp][Nn][Pp].*)|(.*cybergarage.*)");
    private static final Pattern regexFindProtobuf = Pattern.compile("(.*protobuf.*)");
    private static final Pattern regexFindJson = Pattern.compile("(.*[jJ][sS][oO][nN].*)|(.*gson.*)|(.*moshi.*)");

    public static Set<DataProcessing> analyzeValuePoint(ValuePoint valuePoint) {
        Set<DataProcessing> result = new HashSet<>();
        if (isLocalCommunication(valuePoint)) {
            result.add(DataProcessing.FROM_UI);
        }
        result.addAll(analyzeBackwardContexts(valuePoint));
        return result;
    }

    public static Set<DataProcessing> analyzeValuePoint(SValuePoint valuePoint) {
        Set<DataProcessing> result = new HashSet<>();
        // TODO
        // if (isLocalCommunication(valuePoint)) {
        //     result.add(DataProcessing.FROM_UI);
        // }
        // result.addAll(analyzeBackwardContexts(valuePoint));
        return result;
    }

    public static boolean isLocalCommunication(ValuePoint valuePoint) {
        List<UrlInfo> urlInfos = getUrlInfos(valuePoint);
        for (UrlInfo u : urlInfos) {
            if (regex.matcher(u.getDomain()).matches()) {
                return true;
            }

        }
        return false;
    }

    public static List<UrlInfo> getUrlInfos(ValuePoint valuePoint) {
        List<UrlInfo> result = new LinkedList<>();
        Map<Integer, Set<Object>> r = valuePoint.getResult();
        for (int i : r.keySet()) {
            Set<?> urls = r.get(i);
            for (Object current : urls) {
                if (current == null) {
                    continue;
                }
                String currentUrl = StringHelper.objectToString(current);
                if (currentUrl.length() == 0) {
                    continue;
                }
                for (String c : currentUrl.split("\\|\\|")) {
                    int protocolLocation = c.indexOf("://");
                    String protocol = "";
                    if (protocolLocation > 0) {
                        protocol = c.substring(0, protocolLocation).replace("", "");
                        c = c.substring(protocolLocation + 3);
                    }
                    c = c.replace("://", ""); //if the index is 0 :// would be still contained
                    c = c.replace("//", "");


                    int portLocation = c.indexOf(":");
                    int pathLocation = c.indexOf("/");
                    String domain = "";
                    String port = "";
                    String path = "";
                    if (portLocation >= 0 && pathLocation >= 0 && portLocation < pathLocation) {
                        domain = c.substring(0, portLocation).replace("", "");

                        port = (c.substring(portLocation + 1, pathLocation)).replace("", "");
                        path = c.substring(pathLocation);
                    } else if (portLocation >= 0) {
                        domain = c.substring(0, portLocation).replace("", "");
                        port = c.substring(portLocation + 1).replace("", "");
                    } else if (pathLocation >= 0) {
                        domain = c.substring(0, pathLocation).replace("", "");
                        path = c.substring(pathLocation);
                    } else {
                        domain = c.replace("", "");
                    }
                    if (!domain.contains(".")) {
                        domain = "";
                    }
                    result.add(new UrlInfo(protocol, domain, port, path));
                }
            }
        }

        return result;
    }




    public static Set<DataProcessing> analyzeBackwardContexts(ValuePoint valuePoint) {
        Set<DataProcessing> result = new HashSet<>();
        for (BackwardContext backwardContext : valuePoint.getBackwardContexts()) {
            int numberOfShifting = 0;
            Unit lastStmt = backwardContext.getStmtPathTail();
            for (StmtPoint stmtPoint : backwardContext.getStmtPath()) {
                Stmt stmt = (Stmt) stmtPoint.getInstructionLocation();
                if (stmt == lastStmt) {
                    continue;
                }
                if (regexFindEncryption.matcher(stmt.toString()).matches()) {
                    result.add(DataProcessing.ENCRYPTED);
                }
                if (regexFindEncoding.matcher(stmt.toString()).matches()) {
                    result.add(DataProcessing.ENCODED);
                }
                if (regexFindUIInput.matcher(stmt.toString()).matches()) {
                    result.add(DataProcessing.FROM_UI);
                }
                if (regexFindObfuscation.matcher(stmt.toString()).matches()) {
                    numberOfShifting++;
                }
                if (regexFindUPnP.matcher(stmt.toString()).matches()) {
                    result.add(DataProcessing.UPNP);
                }
                if (regexFindProtobuf.matcher(stmt.toString()).matches()) {
                    result.add(DataProcessing.PROTOBUF);
                }
                if (regexFindJson.matcher(stmt.toString()).matches()) {
                    result.add(DataProcessing.JSON);
                }
            }
            if (numberOfShifting > 20) {
                result.add(DataProcessing.OBFUSCATED);
            }
        }
        return result;
    }


}
