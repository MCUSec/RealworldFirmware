package iotscope.forwardexec.objectSimulation.mqtt;

import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Value;
import soot.jimple.*;

import java.util.HashMap;
import java.util.HashSet;

public class FuesourceMqttClientTopicSimulation implements SimulationObjects {


    private static final Logger LOGGER = LoggerFactory.getLogger(FuesourceMqttClientTopicSimulation.class);


    public FuesourceMqttClientTopicSimulation() {
    }

    @Override
    public HashSet<?> handleAssignNewExpression(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {

        return null;
    }


    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        HashSet<String> result = new HashSet<>();

        if (signature.contains("org.fusesource.mqtt.client.Topic")) {
            if (signature.contains("<org.fusesource.mqtt.client.Topic: void <init>(")) {
                result = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
            }
        } else if (signature.contains("<org.fusesource.hawtbuf.UTF8Buffer: void <init>(byte[],int,int")) {
            result = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
        } else if (signature.contains("<org.fusesource.hawtbuf.Buffer: void <init>(org.fusesource.hawtbuf.Buffer")) {
            result = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
        } else if (signature.contains("<org.fusesource.hawtbuf.Buffer: void <init>(byte[]")) {
            return SimulationUtil.getByteArrayContent(expr.getArg(0), currentValues);
        } else if (signature.contains("<org.fusesource.hawtbuf.UTF8Buffer: void <init>(java.lang.String")) {
            result = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
        }

        return result.size() == 0 ? null : result;
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (signature.contains("org.fusesource.hawtbuf.UTF8Buffer")) {
            HashSet<String> result = new HashSet<>();
            if (signature.contains("<org.fusesource.hawtbuf.UTF8Buffer: org.fusesource.hawtbuf.UTF8Buffer utf8(java.lang.String")) {
                result = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
            } else if (signature.contains("<org.fusesource.hawtbuf.UTF8Buffer: org.fusesource.hawtbuf.UTF8Buffer utf8(org.fusesource.hawtbuf.Buffer")) {
                result = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
            } else if (signature.contains("<org.fusesource.hawtbuf.UTF8Buffer: org.fusesource.hawtbuf.")) {
                if (expr instanceof InstanceInvokeExpr) {
                    result = SimulationUtil.getStringContent(((InstanceInvokeExpr) expr).getBase(), currentValues);
                }
            }

            return result;
        } else if (signature.contains("org.fusesource.hawtbuf.Buffer")) {
            HashSet<String> result = new HashSet<>();
            if (signature.contains("<org.fusesource.hawtbuf.Buffer: void ")) {
                result = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
            } else if (signature.contains("<org.fusesource.hawtbuf.Buffer: org.fusesource.hawtbuf.AsciiBuffer(java.lang.String)") ||
                    signature.contains("<org.fusesource.hawtbuf.Buffer: org.fusesource.hawtbuf.UTF8Buffer(java.lang.String)") ||
                    signature.contains("<org.fusesource.hawtbuf.Buffer: org.fusesource.hawtbuf.AsciiBuffer(org.fusesource.hawtbuf.Buffer)") ||
                    signature.contains("<org.fusesource.hawtbuf.Buffer: org.fusesource.hawtbuf.UTF8Buffer(org.fusesource.hawtbuf.Buffer)")) {
                result = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
            } else if (signature.contains("<org.fusesource.hawtbuf.Buffer: org.fusesource.hawtbuf.")) {
                if (expr instanceof InstanceInvokeExpr) {
                    result = SimulationUtil.getStringContent(((InstanceInvokeExpr) expr).getBase(), currentValues);
                }
            }


            return result;
        }
        return null;
    }


    @Override
    public HashSet<?> handleAssignConstant(AssignStmt stmt, Value rightValue, Value leftOp, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignNewArrayExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        NewArrayExpr newArrayExpr = ((NewArrayExpr) rightValue);
        if (newArrayExpr.getBaseType().toString().equals("org.fusesource.mqtt.client.Topic")) {
            return SimulationUtil.initArray("", newArrayExpr, currentValues);
        }
        return null;
    }

    @Override
    public HashSet<?> handleAssignArithmeticExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }


}
