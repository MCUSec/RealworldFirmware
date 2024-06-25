package iotscope.forwardexec.objectSimulation.json;

import com.google.gson.Gson;
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

public class JacksonJsonSimulation implements SimulationObjects {


    private static final Logger LOGGER = LoggerFactory.getLogger(OrgJSONObjectSimulation.class);


    public JacksonJsonSimulation() {
    }

    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (!signature.startsWith("<com.fasterxml.jackson:")) {
            return null;
        }
        HashSet<String> result = new HashSet<>();
        if (signature.contains("<com.fasterxml.jackson.databind.ObjectMapper: void writeValue(") ) {
            Gson gson = new Gson();
            HashSet<Object> arg0 = SimulationUtil.getObjectOrConstant(expr.getArg(1), currentValues);
            arg0.forEach(x -> {
                result.add(gson.toJson(x));
            });
            currentValues.put(expr.getArg(0), result);
        }
        return result;
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (!signature.startsWith("<com.fasterxml.jackson:")) {
            return null;
        }
        HashSet<String> result = new HashSet<>();
        if (signature.equals("<com.fasterxml.jackson.databind.ObjectMapper: byte[] writeValueAsBytes(java.lang.Object)>")
                || signature.equals("<com.fasterxml.jackson.databind.ObjectMapper: java.lang.String writeValueAsString(java.lang.Object)>")) {
            Gson gson = new Gson();
            HashSet<Object> arg0 = SimulationUtil.getObjectOrConstant(expr.getArg(0), currentValues);
            arg0.forEach(x -> {
                result.add(gson.toJson(x));
            });
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
        return null;
    }


    @Override
    public HashSet<?> handleAssignArithmeticExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }


}

