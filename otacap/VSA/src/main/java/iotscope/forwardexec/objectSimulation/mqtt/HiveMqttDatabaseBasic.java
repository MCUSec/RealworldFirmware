package iotscope.forwardexec.objectSimulation.mqtt;

import com.hivemq.client.mqtt.datatypes.MqttClientIdentifier;
import com.hivemq.client.mqtt.datatypes.MqttUtf8String;
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

public class HiveMqttDatabaseBasic implements SimulationObjects {


    private static final Logger LOGGER = LoggerFactory.getLogger(HiveMqttDatabaseBasic.class);


    public HiveMqttDatabaseBasic() {
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
        if (signature.equals("<com.hivemq.client.mqtt.datatypes.MqttUtf8String: com.hivemq.client.mqtt.datatypes.MqttUtf8String of(java.lang.String)>")) {
            HashSet<MqttUtf8String> results = new HashSet<>();
            HashSet<String> arg = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
            arg.forEach(x -> {
                try {
                    results.add(MqttUtf8String.of(x));
                } catch (Exception e) {
                    LOGGER.error(String.format("Could not get Utf8String value of %s", x));
                }
            });
            return results;
        } else if (signature.equals("<com.hivemq.client.mqtt.datatypes.MqttClientIdentifier: com.hivemq.client.mqtt.datatypes.MqttClientIdentifier of(java.lang.String)>")) {
            HashSet<MqttClientIdentifier> results = new HashSet<>();
            HashSet<String> arg = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
            arg.forEach(x -> {
                try {
                    results.add(MqttClientIdentifier.of(x));
                } catch (Exception e) {
                    LOGGER.error(String.format("Could not get Utf8String value of %s", x));
                }
            });
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
    public HashSet<?> handleAssignArithmeticExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }


}
