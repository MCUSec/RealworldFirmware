package iotscope.forwardexec.objectSimulation.network;

import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Value;
import soot.jimple.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.HashSet;

public class JavaNetSocketAddressSimulation implements SimulationObjects {

    private static final Logger LOGGER = LoggerFactory.getLogger(JavaNetSocketAddressSimulation.class);


    public JavaNetSocketAddressSimulation() {
    }


    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        HashSet<InetSocketAddress> result = new HashSet<>();
        switch (signature) {
            case "<java.net.InetSocketAddress: void <init>(java.net.InetAddress,int)>": {

                HashSet<InetAddress> p0 = SimulationUtil.getInetAddress(expr.getArg(0), currentValues);
                HashSet<Integer> p1 = SimulationUtil.getIntContent(expr.getArg(1), currentValues);
                p0.forEach(v0 -> {
                    p1.forEach(v1 -> {
                        try {
                            result.add(new InetSocketAddress(v0, v1));
                        } catch (NullPointerException | IllegalArgumentException e) {
                            LOGGER.error(e.getLocalizedMessage());
                        }
                    });

                });
                break;
            }
            case "<java.net.InetSocketAddress: void <init>(int)>": {

                HashSet<Integer> p0 = SimulationUtil.getIntContent(expr.getArg(0), currentValues);

                p0.forEach(v0 -> {
                    try {
                        result.add(new InetSocketAddress(v0));
                    } catch (NullPointerException  | IllegalArgumentException e) {
                        LOGGER.error(e.getLocalizedMessage());
                    }
                });

                break;
            }
            case "<java.net.InetSocketAddress: void <init>(java.net.String,int)>": {
                HashSet<String> p0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                HashSet<Integer> p1 = SimulationUtil.getIntContent(expr.getArg(1), currentValues);

                p0.forEach(v0 -> {
                    p1.forEach(v1 -> {
                        try {
                            result.add(new InetSocketAddress(v0, v1));
                        } catch (NullPointerException  | IllegalArgumentException e) {
                            LOGGER.error(e.getLocalizedMessage());
                        }
                    });

                });

                break;
            }
        }
        return result.size() == 0 ? null : result;
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        HashSet<InetSocketAddress> result = new HashSet<>();
        switch (signature) {
            case "<java.net.InetSocketAddress: java.net.InetSocketAddress createUnresolved(java.net.String,int)>": {
                HashSet<String> p0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                HashSet<Integer> p1 = SimulationUtil.getIntContent(expr.getArg(1), currentValues);

                p0.forEach(v0 -> {
                    p1.forEach(v1 -> {
                        try {
                            result.add(InetSocketAddress.createUnresolved(v0, v1));
                        } catch (NullPointerException  | IllegalArgumentException e) {
                            LOGGER.error(e.getLocalizedMessage());
                        }
                    });

                });

                break;
            }
            case "<java.net.InetSocketAddress: java.lang.String getHostName()>": {

                HashSet<InetSocketAddress> p0 = SimulationUtil.getInetSocketAddress(expr.getArg(0), currentValues);
                HashSet<String> stringResult = new HashSet<>();

                p0.forEach(v0 -> {
                    stringResult.add(v0 != null ? v0.getHostName() : "");
                });
                return stringResult;

            }
            case "<java.net.InetSocketAddress: java.lang.String getHostString()>": {
                HashSet<InetSocketAddress> p0 = SimulationUtil.getInetSocketAddress(expr.getArg(0), currentValues);
                HashSet<String> stringResult = new HashSet<>();

                p0.forEach(v0 -> {
                    stringResult.add(v0 != null ? v0.getHostString() : "");
                });
                return stringResult;

            }
            case "<java.net.InetSocketAddress: java.lang.String toString()>": {
                HashSet<InetSocketAddress> p0 = SimulationUtil.getInetSocketAddress(expr.getArg(0), currentValues);
                HashSet<String> stringResult = new HashSet<>();

                p0.forEach(v0 -> {
                    stringResult.add(v0 != null ? v0.toString() : "");
                });
                return stringResult;

            }
        }
        return result;
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
        if (newArrayExpr.getBaseType().toString().equals("java.net.SocketAddress")) {
            return SimulationUtil.initArray(null, newArrayExpr, currentValues);
        }
        return null;
    }

    @Override
    public HashSet<?> handleAssignArithmeticExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

}
