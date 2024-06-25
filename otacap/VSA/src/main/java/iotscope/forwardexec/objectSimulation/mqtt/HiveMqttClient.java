package iotscope.forwardexec.objectSimulation.mqtt;

import com.hivemq.client.mqtt.MqttClient;
import com.hivemq.client.mqtt.MqttClientBuilder;
import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

public class HiveMqttClient implements SimulationObjects {


    private static final Logger LOGGER = LoggerFactory.getLogger(HiveMqttClient.class);


    public HiveMqttClient() {
    }

    @Override
    public HashSet<?> handleAssignNewExpression(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        if (rightValue.getType().toString().equals("com.hivemq.client.mqtt.MqttClientBuilder") ||
                rightValue.getType().toString().equals("com.hivemq.client.mqtt.mqtt3.Mqtt3Client") ||
                rightValue.getType().toString().equals("com.hivemq.client.mqtt.mqtt5.Mqtt5Client")
        ) {
            return initBuilder();
        }
        return null;
    }


    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (signature.contains("com.hivemq.client.mqtt")) {
            HashSet<MqttClientBuilder> clientBuilderResults = new HashSet<>();
            Value base = ((InstanceInvokeExpr) expr).getBase();
            HashSet<MqttClientBuilder> currentClientBuilder = SimulationUtil.getHivemqClientBuilder(base, currentValues);
            List<MqttClientBuilder> clientList = Arrays.asList(currentClientBuilder.toArray(new MqttClientBuilder[]{}));
            if (signature.contains("serverAddress(java.net.InetSocketAddress)")) {
                HashSet<InetSocketAddress> arg0 = SimulationUtil.getInetSocketAddress(expr.getArg(0), currentValues);
                int i = 0;
                for (InetSocketAddress s : arg0) {
                    if (i < clientList.size()) {
                        clientBuilderResults.add(clientList.get(i).serverAddress(s));
                    } else {
                        clientBuilderResults.add(MqttClient.builder().serverAddress(s));
                    }
                    i++;
                }

            } else if (signature.contains("serverHost(java.net.InetAddress)")) {
                HashSet<InetAddress> arg0 = SimulationUtil.getInetAddress(expr.getArg(0), currentValues);
                int i = 0;
                for (InetAddress s : arg0) {
                    if (i < clientList.size()) {
                        clientBuilderResults.add(clientList.get(i).serverHost(s));
                    } else {
                        clientBuilderResults.add(MqttClient.builder().serverHost(s));
                    }
                    i++;
                }
            } else if (signature.contains("serverHost(java.lang.String)")) {
                // just return base
                HashSet<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                int i = 0;
                for (String s : arg0) {
                    if (i < clientList.size()) {
                        clientBuilderResults.add(clientList.get(i).serverHost(s));
                    } else {
                        clientBuilderResults.add(MqttClient.builder().serverHost(s));
                    }
                    i++;
                }
            } else if (signature.contains("serverPort(int)")) {
                HashSet<Integer> arg0 = SimulationUtil.getIntContent(expr.getArg(0), currentValues);
                int i = 0;
                for (int s : arg0) {
                    if (i < clientList.size()) {
                        clientBuilderResults.add(clientList.get(i).serverPort(s));
                    } else {
                        clientBuilderResults.add(MqttClient.builder().serverPort(s));
                    }
                    i++;
                }
            } else if (signature.contains("build")) {
                HashSet<MqttClient> clientResults = new HashSet<>();
                currentClientBuilder.forEach(x -> {
                    clientResults.add(x.useMqttVersion3().build());
                });
                return clientResults;
            } else {
                //return the previous builder
                clientBuilderResults = currentClientBuilder;
            }

            return clientBuilderResults;
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


    private HashSet<MqttClientBuilder> initBuilder() {
        HashSet<MqttClientBuilder> tmp = new HashSet<>();
        tmp.add(MqttClient.builder());
        return tmp;
    }


}
