package iotscope.forwardexec.objectSimulation.network;

import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Value;
import soot.jimple.*;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

public class JavaNetInetAddressSimulation implements SimulationObjects {

    private static final Logger LOGGER = LoggerFactory.getLogger(JavaNetInetAddressSimulation.class);


    public JavaNetInetAddressSimulation() {
    }


    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (signature.contains("java.net.InetAddress")) {
            HashSet<InetAddress> inetAddresses = new HashSet<>();
            switch (signature) {
                case "<java.net.InetAddress: java.net.InetAddress getByName(java.lang.String)>": {
                    HashSet<String> parameters = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                    parameters.forEach(v -> {
                        try {
                            inetAddresses.add(InetAddress.getByName(v));
                        } catch (UnknownHostException | NullPointerException e) {
                            try {
                                inetAddresses.add(InetAddress.getByName(SimulationUtil.findDomain(v)));
                            } catch (UnknownHostException | NullPointerException e2) {
                                LOGGER.error(e2.getLocalizedMessage());
                            }
                        }
                    });
                    return inetAddresses;
                }
                case "<java.net.InetAddress[]: java.net.InetAddress getAllByName(java.lang.String)>": {
                    HashSet<String> parameters = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                    HashSet<List<InetAddress>> resultArray = new HashSet<>();

                    parameters.forEach(v -> {
                        try {
                            resultArray.add(Arrays.asList(InetAddress.getAllByName(v)));
                        } catch (UnknownHostException | NullPointerException e) {
                            try {
                                resultArray.add(Arrays.asList(InetAddress.getAllByName(SimulationUtil.findDomain(v))));
                            } catch (UnknownHostException | NullPointerException e2) {
                                LOGGER.error(e2.getLocalizedMessage());
                            }
                        }
                    });
                    return resultArray;
                }
                case "<java.net.InetAddress: java.net.InetAddress getByAddress(java.lang.String,byte[])>": {
                    HashSet<String> p0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                    HashSet<byte[]> p1 = SimulationUtil.getByteArrayContent(expr.getArg(1), currentValues);
                    p0.forEach(v -> p1.forEach(v1 -> {
                        try {
                            inetAddresses.add(InetAddress.getByAddress(v, v1));
                        } catch (UnknownHostException | NullPointerException e) {
                            try {
                                inetAddresses.add(InetAddress.getByAddress(SimulationUtil.findDomain(v), v1));
                            } catch (UnknownHostException | NullPointerException e2) {
                                LOGGER.error(e2.getLocalizedMessage());
                            }
                        }
                    }));
                    break;
                }
                case "<java.net.InetAddress: java.net.InetAddress getByAddress(byte[])>": {
                    HashSet<byte[]> p0 = SimulationUtil.getByteArrayContent(expr.getArg(0), currentValues);
                    p0.forEach(v -> {
                        try {
                            inetAddresses.add(InetAddress.getByAddress(v));
                        } catch (UnknownHostException | NullPointerException e) {
                            //e.printStackTrace();
                            LOGGER.error(e.getLocalizedMessage());
                        }
                    });

                    break;
                }
                case "<java.net.InetAddress: java.net.InetAddress getLocalHost()>": {
                    try {
                        inetAddresses.add(InetAddress.getLocalHost());
                    } catch (UnknownHostException e) {
                        LOGGER.error(e.getLocalizedMessage());
                    }
                    break;
                }
                case "<java.net.InetAddress: java.net.InetAddress getLoopbackAddress()>": {
                    inetAddresses.add(InetAddress.getLoopbackAddress());
                    break;
                }
                case "<java.net.InetAddress: java.lang.String getCanonicalHostName()>": {
                    HashSet<String> inetAddressString = new HashSet<>();
                    HashSet<InetAddress> parameters = SimulationUtil.getInetAddress(((InstanceInvokeExpr) expr).getBase(), currentValues);
                    parameters.forEach(v -> {
                        inetAddressString.add(v != null ? v.getCanonicalHostName() : "");
                    });
                    return inetAddressString;
                }
                case "<java.net.InetAddress: java.lang.String getHostAddress()>": {
                    HashSet<String> inetAddressString = new HashSet<>();
                    HashSet<InetAddress> parameters = SimulationUtil.getInetAddress(((InstanceInvokeExpr) expr).getBase(), currentValues);
                    parameters.forEach(v -> {
                        inetAddressString.add(v != null ? v.getHostAddress() : "");
                    });
                    return inetAddressString;
                }
                case "<java.net.InetAddress: java.lang.String getHostName()>": {
                    HashSet<String> inetAddressString = new HashSet<>();

                    HashSet<InetAddress> parameters = SimulationUtil.getInetAddress(((InstanceInvokeExpr) expr).getBase(), currentValues);
                    parameters.forEach(v -> {
                        inetAddressString.add(v != null ? v.getHostName() : "");
                    });
                    return inetAddressString;
                }
                case "<java.net.InetAddress: java.lang.String toString()>": {
                    HashSet<String> inetAddressString = new HashSet<>();
                    HashSet<InetAddress> parameters = SimulationUtil.getInetAddress(((InstanceInvokeExpr) expr).getBase(), currentValues);
                    parameters.forEach(v -> {
                        inetAddressString.add(v != null ? v.toString() : "");
                    });
                    return inetAddressString;
                }
            }
            return inetAddresses;
        }
        return null;
    }

    @Override
    public HashSet<?> handleAssignNewExpression(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignConstant(AssignStmt stmt, Value rightValue, Value leftOp, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignNewArrayExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        NewArrayExpr newArrayExpr = ((NewArrayExpr) rightValue);
        if (newArrayExpr.getBaseType().toString().equals("java.net.InetAddress")) {
            return SimulationUtil.initArray(null, newArrayExpr, currentValues);
        }
        return null;
    }

    @Override
    public HashSet<?> handleAssignArithmeticExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }


}
