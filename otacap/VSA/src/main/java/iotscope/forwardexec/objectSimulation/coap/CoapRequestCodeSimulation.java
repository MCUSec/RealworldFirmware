package iotscope.forwardexec.objectSimulation.coap;

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

public class CoapRequestCodeSimulation implements SimulationObjects {


    private static final Logger LOGGER = LoggerFactory.getLogger(CoapRequestCodeSimulation.class);


    public CoapRequestCodeSimulation() {
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
        if (rightValue.toString().contains("org.ws4d.coap.core.enumerations")) {
            HashSet<String> result = new HashSet<>();
            switch (rightValue.toString()) {
                case "<org.ws4d.coap.core.enumerations.CoapRequestCode: org.ws4d.coap.core.enumerations.CoapRequestCode GET>": {
                    result.add("GET");
                }
                break;
                case "<org.ws4d.coap.core.enumerations.CoapRequestCode: org.ws4d.coap.core.enumerations.CoapRequestCode POST>": {
                    result.add("POST");
                }
                break;
                case "<org.ws4d.coap.core.enumerations.CoapRequestCode: org.ws4d.coap.core.enumerations.CoapRequestCode PUT>": {
                    result.add("PUT");
                }
                break;
                case "<org.ws4d.coap.core.enumerations.CoapRequestCode: org.ws4d.coap.core.enumerations.CoapRequestCode DELETE>": {
                    result.add("DELETE");
                }
                break;
                default:
                    LOGGER.error("{} is currently not supported by the OkHttpSimulation", rightValue.toString());
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
