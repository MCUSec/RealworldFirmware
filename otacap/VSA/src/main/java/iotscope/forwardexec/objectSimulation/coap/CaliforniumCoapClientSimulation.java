package iotscope.forwardexec.objectSimulation.coap;

import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;
import okhttp3.HttpUrl;
import okhttp3.Request;
import org.eclipse.californium.core.CoapClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;

import java.net.URL;
import java.util.*;

public class CaliforniumCoapClientSimulation implements SimulationObjects {


    private static final Logger LOGGER = LoggerFactory.getLogger(CaliforniumCoapClientSimulation.class);


    public CaliforniumCoapClientSimulation() {
    }

    @Override
    public HashSet<?> handleAssignNewExpression(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {

        return null;
    }


    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (signature.contains("<org.eclipse.californium.core.CoapClient$Builder: void <init>(java.lang.String,int)>")) {
            HashSet<CoapClient.Builder> coapClient = new HashSet<>();
            List<String> arg0 = new ArrayList<>(SimulationUtil.getStringContent(expr.getArg(0), currentValues));
            List<Integer> arg1 = new ArrayList<>(SimulationUtil.getIntContent(expr.getArg(1), currentValues));
            while (arg0.size() < arg1.size()) {
                arg0.add("");
            }
            while (arg1.size() < arg0.size()) {
                arg1.add(0);
            }
            Iterator<String> arg0Iterator = arg0.iterator();
            Iterator<Integer> arg1Iterator = arg1.iterator();

            while (arg0Iterator.hasNext() && arg1Iterator.hasNext()) {
                coapClient.add(new CoapClient.Builder(arg0Iterator.next(), arg1Iterator.next()));
            }

            return coapClient;
        }
        return null;
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (signature.contains("org.eclipse.californium")) {
            HashSet<CoapClient.Builder> coapClient = new HashSet<>();
            switch (signature) {
                case "<org.eclipse.californium.core.CoapClient$Builder: org.eclipse.californium.core.CoapClient$Builder host(java.lang.String)>": {
                    Value from = ((InstanceInvokeExpr) expr).getBase();
                    HashSet<CoapClient.Builder> coapBuilders = SimulationUtil.getCoapClientBuilder(from, currentValues);
                    HashSet<String> hostValues = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                    List<String> hostList = Arrays.asList(hostValues.toArray(new String[]{}));
                    int i = 0;
                    for (CoapClient.Builder b : coapBuilders) {
                        if (b != null) {
                            coapClient.add(b.host(hostList.get(i % hostList.size())));
                            i++;
                        }
                    }
                }
                break;
                case "<org.eclipse.californium.core.CoapClient$Builder: org.eclipse.californium.core.CoapClient$Builder path(java.lang.String[])>": {
                    Value from = ((InstanceInvokeExpr) expr).getBase();
                    HashSet<CoapClient.Builder> coapBuilders = SimulationUtil.getCoapClientBuilder(from, currentValues);
                    HashSet<List<String>> pathValues = SimulationUtil.getStringArrayContent(expr.getArg(0), currentValues);
                    List<String[]> hostList = new ArrayList<>();
                    for (List<String> current : pathValues) {
                        hostList.add(current.toArray(new String[]{}));
                    }
                    int i = 0;
                    for (CoapClient.Builder b : coapBuilders) {
                        if (b != null) {
                            coapClient.add(b.path(hostList.get(i % hostList.size())));
                            i++;
                        }
                    }
                }
                break;
                case "<org.eclipse.californium.core.CoapClient$Builder: org.eclipse.californium.core.CoapClient$Builder port(int)>": {
                    Value from = ((InstanceInvokeExpr) expr).getBase();
                    HashSet<CoapClient.Builder> coapBuilders = SimulationUtil.getCoapClientBuilder(from, currentValues);
                    HashSet<Integer> portValues = SimulationUtil.getIntContent(expr.getArg(0), currentValues);
                    List<Integer> portList = Arrays.asList(portValues.toArray(new Integer[]{}));
                    int i = 0;
                    for (CoapClient.Builder b : coapBuilders) {
                        if (b != null) {
                            coapClient.add(b.port(portList.get(i % portList.size())));
                            i++;
                        }
                    }

                    break;
                }
                case "<org.eclipse.californium.core.CoapClient$Builder: org.eclipse.californium.core.CoapClient$Builder query(java.lang.String[])>": {
                    Value from = ((InstanceInvokeExpr) expr).getBase();
                    HashSet<CoapClient.Builder> coapBuilders = SimulationUtil.getCoapClientBuilder(from, currentValues);
                    HashSet<List<String>> pathValues = SimulationUtil.getStringArrayContent(expr.getArg(0), currentValues);
                    List<String[]> hostList = new ArrayList<>();
                    for (List<String> current : pathValues) {
                        hostList.add(current.toArray(new String[]{}));
                    }
                    int i = 0;
                    for (CoapClient.Builder b : coapBuilders) {
                        if (b != null) {
                            coapClient.add(b.query(hostList.get(i % hostList.size())));
                            i++;
                        }
                    }
                    break;
                }
                case "<org.eclipse.californium.core.CoapClient$Builder: org.eclipse.californium.core.CoapClient$Builder scheme(java.lang.String)>": {
                    Value from = ((InstanceInvokeExpr) expr).getBase();
                    HashSet<CoapClient.Builder> coapBuilders = SimulationUtil.getCoapClientBuilder(from, currentValues);
                    HashSet<String> schemeValues = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                    List<String> schemeList = Arrays.asList(schemeValues.toArray(new String[]{}));
                    int i = 0;
                    for (CoapClient.Builder b : coapBuilders) {
                        if (b != null) {
                            coapClient.add(b.scheme(schemeList.get(i % schemeList.size())));
                            i++;
                        }
                    }
                }
                break;
                case "<org.eclipse.californium.core.CoapClient: org.eclipse.californium.core.CoapClient$Builder create()>": {
                    Value from = ((InstanceInvokeExpr) expr).getBase();
                    HashSet<CoapClient.Builder> coapBuilders = SimulationUtil.getCoapClientBuilder(from, currentValues);
                    HashSet<CoapClient> result = new HashSet<>();
                    for (CoapClient.Builder b : coapBuilders) {
                        if (b != null) {
                            result.add(b.create());
                        }
                    }

                    return result;
                }
                default:
                    LOGGER.error("{} is currently not supported by the OkHttpSimulation", signature);
                    break;
            }
            return coapClient;
        }
        return null;
    }


    @Override
    public HashSet<?> handleAssignConstant(AssignStmt stmt, Value rightValue, Value leftOp, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignNewArrayExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {

        return null;
    }

    @Override
    public HashSet<?> handleAssignArithmeticExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }



}
