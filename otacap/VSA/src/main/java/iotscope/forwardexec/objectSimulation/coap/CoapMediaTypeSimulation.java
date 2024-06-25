package iotscope.forwardexec.objectSimulation.coap;

import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;

import java.util.HashMap;
import java.util.HashSet;

public class CoapMediaTypeSimulation implements SimulationObjects {


    private static final Logger LOGGER = LoggerFactory.getLogger(CoapMediaTypeSimulation.class);


    public CoapMediaTypeSimulation() {
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
            switch (signature) {
                case "<org.ws4d.coap.core.enumerations.CoapMediaType: org.ws4d.coap.core.enumerations.CoapMediaType parse(int)>":
                    HashSet<Integer> arg1 = SimulationUtil.getIntContent(expr.getArg(1), currentValues);
                    for (Integer i : arg1) {
                        if (i != null) {
                            if (i == 0) {
                                result.add("text/plain; charset=utf-8");
                            } else if (i == 40) {
                                result.add("application/link-format");
                            } else if (i == 41) {
                                result.add("application/xml");
                            } else if (i == 42) {
                                result.add("application/octet-stream");
                            } else if (i == 47) {
                                result.add("application/exi");
                            } else if (i == 50) {
                                result.add("application/json");
                            }
                        }
                    }
                    break;
                case "<org.ws4d.coap.core.enumerations.CoapMediaType: java.lang.String getMimeType()>": {
                    Value from = ((InstanceInvokeExpr) expr).getBase();
                    return SimulationUtil.getStringContent(from, currentValues);
                }
                default:
                    LOGGER.error("{} is currently not supported by the OkHttpSimulation", signature);
                    break;
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
                case "<org.ws4d.coap.core.enumerations.CoapMediaType: org.ws4d.coap.core.enumerations.CoapMediaType text_plain>": {
                    result.add("text/plain; charset=utf-8");
                }
                break;
                case "<org.ws4d.coap.core.enumerations.CoapMediaType: org.ws4d.coap.core.enumerations.CoapMediaType link_format>": {
                    result.add("application/link-format");
                }
                break;
                case "<org.ws4d.coap.core.enumerations.CoapMediaType: org.ws4d.coap.core.enumerations.CoapMediaType xml>": {
                    result.add("application/xml");
                }
                break;
                case "<org.ws4d.coap.core.enumerations.CoapMediaType: org.ws4d.coap.core.enumerations.CoapMediaType octet_stream>": {
                    result.add("application/octet-stream");
                }
                break;
                case "<org.ws4d.coap.core.enumerations.CoapMediaType: org.ws4d.coap.core.enumerations.CoapMediaType exi>": {
                    result.add("application/exi");
                }
                break;
                case "<org.ws4d.coap.core.enumerations.CoapMediaType: org.ws4d.coap.core.enumerations.CoapMediaType json>": {
                    result.add("application/json");
                }
                break;
                default:
                    LOGGER.error("{} is currently not supported by the OkHttpSimulation", rightValue);
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
