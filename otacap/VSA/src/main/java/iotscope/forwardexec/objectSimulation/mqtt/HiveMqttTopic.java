package iotscope.forwardexec.objectSimulation.mqtt;

import com.hivemq.client.internal.mqtt.datatypes.MqttTopicImplBuilder;
import com.hivemq.client.mqtt.datatypes.MqttTopic;
import com.hivemq.client.mqtt.datatypes.MqttTopicBuilder;
import com.hivemq.client.mqtt.datatypes.MqttTopicFilter;
import com.hivemq.client.mqtt.datatypes.MqttTopicFilterBuilder;
import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

public class HiveMqttTopic implements SimulationObjects {

    private static final Logger LOGGER = LoggerFactory.getLogger(HiveMqttTopic.class);


    public HiveMqttTopic() {
    }

    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {

        return null;
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (signature.contains("com.hivemq.client.mqtt.datatypes.MqttTopic")) {
            if (signature.equals("<com.hivemq.client.mqtt.database.MqttTopic: com.hivemq.client.mqtt.database.MqttTopic of(java.lang.String)>")) {
                HashSet<String> arguments = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                HashSet<MqttTopic> results = new HashSet<>();
                for (String a : arguments) {
                    try {
                        results.add(MqttTopic.of(a));
                    } catch (Exception e) {
                        LOGGER.error(e.getLocalizedMessage());
                        LOGGER.error(String.format("could not get MqttTopic of %s", a));
                    }
                }
                return results;

            } else if (signature.equals("<com.hivemq.client.mqtt.database.MqttTopicBuilder: com.hivemq.client.mqtt.database.MqttTopicBuilder addLevel(java.lang.String)>")) {
                Value base = ((InstanceInvokeExpr) expr).getBase();
                List<MqttTopicBuilder> currentTopicBuilder = Arrays.asList(SimulationUtil.getHivemqTopicBuilder(base, currentValues).toArray(new MqttTopicBuilder[]{}));
                HashSet<String> arguments = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                HashSet<MqttTopicBuilder> results = new HashSet<>();
                int i = 0;
                for (String s : arguments) {
                    if (s != null) {
                        if (i < arguments.size()) {
                            results.add(currentTopicBuilder.get(i).addLevel(s));
                        } else {
                            MqttTopicBuilder current = MqttTopic.builder();
                            results.add(current.addLevel(s));
                        }
                    }
                    i++;
                }
                return results;
            } else if (signature.equals("<com.hivemq.client.mqtt.database.MqttTopicBuilder: com.hivemq.client.mqtt.database.MqttTopic build()>")) {
                Value base = ((InstanceInvokeExpr) expr).getBase();
                HashSet<MqttTopicBuilder> currentTopicBuilder = SimulationUtil.getHivemqTopicBuilder(base, currentValues);
                HashSet<MqttTopic> results = new HashSet<>();
                for (MqttTopicBuilder builder : currentTopicBuilder) {
                    try {
                        results.add(((MqttTopicImplBuilder) builder).build());
                    } catch (Exception e) {
                        LOGGER.error(e.getLocalizedMessage());
                        LOGGER.error(String.format("could not build MqttTopicBuilder of %s", builder));
                    }
                    return results;
                }
            } else if (signature.startsWith("<com.hivemq.client.mqtt.database.MqttTopicBuilder: com.hivemq.client.mqtt.database.MqttTopicBuilder")) {
                Value base = ((InstanceInvokeExpr) expr).getBase();
                return SimulationUtil.getHivemqTopicBuilder(base, currentValues);
            } else if (signature.startsWith("<com.hivemq.client.mqtt.database.MqttTopic: com.hivemq.client.mqtt.database.MqttTopic")) {
                Value base = ((InstanceInvokeExpr) expr).getBase();
                return SimulationUtil.getHivemqTopic(base, currentValues);
            }

        } else if (signature.contains("com.hivemq.client.mqtt.database.MqttTopicFilter")) {

            if (signature.equals("<com.hivemq.client.mqtt.database.MqttTopicFilter: com.hivemq.client.mqtt.database.MqttTopicFilter of(java.lang.String)>")) {
                HashSet<String> arguments = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                HashSet<MqttTopicFilter> results = new HashSet<>();
                for (String a : arguments) {
                    try {
                        results.add(MqttTopicFilter.of(a));
                    } catch (Exception e) {
                        LOGGER.error(e.getLocalizedMessage());
                        LOGGER.error(String.format("could not get MqttTopic of %s", a));
                    }
                }
                return results;

            } else if (signature.equals("<com.hivemq.client.mqtt.database.MqttTopicFilterBuilder: com.hivemq.client.mqtt.database.MqttTopicFilterBuilder addLevel(java.lang.String)>")) {
                Value base = ((InstanceInvokeExpr) expr).getBase();
                List<MqttTopicFilterBuilder> currentTopicBuilder = Arrays.asList(SimulationUtil.getHivemqTopicFilterBuilder(base, currentValues).toArray(new MqttTopicFilterBuilder[]{}));
                HashSet<String> arguments = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                HashSet<MqttTopicFilterBuilder> results = new HashSet<>();
                int i = 0;
                for (String s : arguments) {
                    if (s != null) {
                        if (i < arguments.size()) {
                            results.add(currentTopicBuilder.get(i).addLevel(s));
                        } else {
                            MqttTopicFilterBuilder current = MqttTopicFilter.builder();
                            results.add(current.addLevel(s));
                        }
                    }
                    i++;
                }
                return results;
            } else if (signature.startsWith("<com.hivemq.client.mqtt.database.MqttTopicFilterBuilder: com.hivemq.client.mqtt.database.MqttTopicFilterBuilder")) {
                Value base = ((InstanceInvokeExpr) expr).getBase();
                return SimulationUtil.getHivemqTopicFilterBuilder(base, currentValues);
            } else if (signature.startsWith("<com.hivemq.client.mqtt.database.MqttTopicFilter: com.hivemq.client.mqtt.database.MqttTopicFilter")) {
                Value base = ((InstanceInvokeExpr) expr).getBase();
                return SimulationUtil.getHivemqTopicFilter(base, currentValues);
            }


        }
        return null;
    }

    @Override
    public HashSet<?> handleAssignNewExpression(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        if (rightValue.getType().toString().equals("com.hivemq.client.mqtt.database.MqttTopicBuilder")) {
            HashSet<MqttTopicBuilder> tmp = new HashSet<>();
            tmp.add(MqttTopic.builder());
            return tmp;
        } else if (rightValue.getType().toString().equals("com.hivemq.client.mqtt.database.MqttTopicFilterBuilder")) {
            HashSet<MqttTopicFilterBuilder> tmp = new HashSet<>();
            tmp.add(MqttTopicFilter.builder());
            return tmp;
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
