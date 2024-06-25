package iotscope.forwardexec.objectSimulation.xmpp;

import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;

import java.util.HashMap;
import java.util.HashSet;

public class JiveSoftwareSmackConstants implements SimulationObjects {


    private static final Logger LOGGER = LoggerFactory.getLogger(JiveSoftwareSmackConstants.class);


    public JiveSoftwareSmackConstants() {
    }

    @Override
    public HashSet<?> handleAssignNewExpression(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {

        return null;
    }


    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (signature.contains("org.ws4d.coap.core.enumerations")) {
            HashSet<String> result = new HashSet<>();
            if ("<org.ws4d.coap.core.enumerations.CoapRequestCode: org.ws4d.coap.core.enumerations.CoapRequestCode parse(int)>".equals(signature)) {
                HashSet<Integer> arg1 = SimulationUtil.getIntContent(expr.getArg(1), currentValues);
                for (Integer i : arg1) {
                    if (i != null) {
                        if (i == 1) {
                            result.add("GET");
                        } else if (i == 2) {
                            result.add("POST");
                        } else if (i == 3) {
                            result.add("PUT");
                        } else if (i == 4) {
                            result.add("DELETE");
                        }
                    }
                }
            } else {
                LOGGER.error("{} is currently not supported by the OkHttpSimulation", signature);
            }
            return result;
        }
        return null;
    }


    @Override
    public HashSet<?> handleAssignConstant(AssignStmt stmt, Value rightValue, Value leftOp, HashMap<Value, HashSet<?>> currentValues) {
        if (rightValue.toString().contains("org.jivesoftware.smack.packet.Message$Type") ||
                rightValue.toString().contains("org.jivesoftware.smack.ConnectionConfiguration$SecurityMode")) {
            HashSet<String> result = new HashSet<>();
            switch (rightValue.toString()) {
                case "<org.jivesoftware.smack.packet.Message$Type: org.jivesoftware.smack.packet.Message$Type chat>": {
                    result.add("chat");
                }
                break;
                case "<org.jivesoftware.smack.packet.Message$Type: org.jivesoftware.smack.packet.Message$Type error>": {
                    result.add("error");
                }
                break;
                case "<org.jivesoftware.smack.packet.Message$Type: org.jivesoftware.smack.packet.Message$Type groupchat>": {
                    result.add("groupchat");
                }
                break;
                case "<org.jivesoftware.smack.packet.Message$Type: org.jivesoftware.smack.packet.Message$Type headline>": {
                    result.add("headline");
                }
                break;
                case "<org.jivesoftware.smack.packet.Message$Type: org.jivesoftware.smack.packet.Message$Type normal>": {
                    result.add("normal");
                }
                break;
                case "<org.jivesoftware.smack.ConnectionConfiguration$SecurityMode: org.jivesoftware.smack.ConnectionConfiguration$SecurityMode disabled>": {
                    result.add("disabled");
                }
                break;
                case "<org.jivesoftware.smack.ConnectionConfiguration$SecurityMode: org.jivesoftware.smack.ConnectionConfiguration$SecurityMode ifpossible>": {
                    result.add("ifpossible");
                }
                break;
                case "<org.jivesoftware.smack.ConnectionConfiguration$SecurityMode: org.jivesoftware.smack.ConnectionConfiguration$SecurityMode required>": {
                    result.add("required");
                }
                break;
                default:
                    LOGGER.error("{} is currently not supported by the JiveConstantSimulation", rightValue.toString());
                    break;
            }
            return result;
        }
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
