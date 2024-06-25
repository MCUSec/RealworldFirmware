package iotscope.forwardexec.objectSimulation.cloud;

import com.hivemq.client.mqtt.MqttClient;
import com.hivemq.client.mqtt.MqttClientBuilder;
import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

public class AwsCredentialSimulation implements SimulationObjects {


    private static final Logger LOGGER = LoggerFactory.getLogger(AwsCredentialSimulation.class);


    public AwsCredentialSimulation() {
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
        if (signature.equals("<com.amazonaws.auth.BasicAWSCredentials: void <init>(java.lang.String,java.lang.String)>")) {
            HashSet<AwsCredentialDto> awsCredentials = new HashSet<>();
            List<String> arg0 = new ArrayList<>(SimulationUtil.getStringContent(expr.getArg(0),currentValues));
            List<String> arg1 = new ArrayList<>(SimulationUtil.getStringContent(expr.getArg(1),currentValues));
            while (arg0.size()<arg1.size()) {
                arg0.add("");
            }

            while (arg1.size()<arg0.size()) {
                arg1.add("");
            }

            for (int i = 0; i<arg0.size(); i++) {
                awsCredentials.add(new AwsCredentialDto(arg0.get(i), arg1.get(i)));
            }

            return awsCredentials;
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
