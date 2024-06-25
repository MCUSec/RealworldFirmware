package iotscope.forwardexec.objectSimulation.mqtt;

import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.internal.AbstractInstanceInvokeExpr;

import java.util.HashMap;
import java.util.HashSet;

public class PahoMqtt3Message implements SimulationObjects {


    private static final Logger LOGGER = LoggerFactory.getLogger(PahoMqtt3Message.class);


    public PahoMqtt3Message() {
    }


    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        HashSet<MqttMessage> results = new HashSet<>();
        if (signature.equals("<org.eclipse.paho.client.mqttv3.MqttMessage: void <init>()>")) {
            results.add(new MqttMessage());
        } else if (signature.equals("<org.eclipse.paho.client.mqttv3.MqttMessage: void <init>(byte[])>")) {
            HashSet<byte[]> arg0 = SimulationUtil.getByteArrayContent(expr.getArg(0), currentValues);
            HashSet<MqttMessage> finalResults = results;
            arg0.forEach(x -> finalResults.add(new MqttMessage(x)));
            results = finalResults;
        }

        return results.size() == 0 ? null : results;
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (signature.contains("org.eclipse.paho.client.mqttv3.MqttMessage")) {
            HashSet<MqttMessage> results = new HashSet<>();
            if (signature.equals("<org.eclipse.paho.client.mqttv3.MqttMessage: byte[] getPayload()>")) {
                HashSet<MqttMessage> arg0 = SimulationUtil.getMqttMessage(expr.getArg(0), currentValues);
                HashSet<byte[]> resultBytes = new HashSet<>();
                arg0.forEach(x -> {
                    if (x != null) {
                        resultBytes.add(x.getPayload());
                    }
                });
                return resultBytes;
            } else if (signature.equals("<org.eclipse.paho.client.mqttv3.MqttMessage: void setPayload(byte[])>")) {
                AbstractInstanceInvokeExpr instanceInvokeExpr = (AbstractInstanceInvokeExpr) expr;
                HashSet<MqttMessage> base = SimulationUtil.getMqttMessage(instanceInvokeExpr.getBase(), currentValues);
                HashSet<byte[]> arg0 = SimulationUtil.getByteArrayContent(expr.getArg(0), currentValues);
                base.clear(); // we can clear it because we set new values anyway
                for (byte[] byteArray : arg0) {
                    if (byteArray != null) {
                        base.add(new MqttMessage(byteArray));
                    }
                }
                results = base;
            } else if (signature.equals("<org.eclipse.paho.client.mqttv3.MqttMessage: java.lang.String toString()>")) {
                AbstractInstanceInvokeExpr instanceInvokeExpr = (AbstractInstanceInvokeExpr) expr;
                HashSet<MqttMessage> base = SimulationUtil.getMqttMessage(instanceInvokeExpr.getBase(), currentValues);
                HashSet<String> toString = new HashSet<>();
                base.forEach(x -> {
                    if (x != null) {
                        toString.add(x.toString());
                    }
                });
                return toString;
            }
            return results;
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
    public HashSet<?> handleAssignNewExpression(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignArithmeticExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }


}
