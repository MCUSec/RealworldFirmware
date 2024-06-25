package iotscope.forwardexec.objectSimulation.network;

import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.NewArrayExpr;

import java.util.HashMap;
import java.util.HashSet;

public class ApacheSimulation implements SimulationObjects {

    private static final Logger LOGGER = LoggerFactory.getLogger(JavaNetUrlSimulation.class);


    public ApacheSimulation() {
    }


    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (signature.contains("org.apache.hc.core5.http.io.entity")) {
            switch (signature) {
                case "<org.apache.hc.core5.http.io.entity.StringEntity: void <init>(java.lang.String,java.nio.charset.Charset,boolean)>":
                case "<org.apache.hc.core5.http.io.entity.StringEntity: void <init>(java.lang.String,java.nio.charset.Charset)>":
                case "<org.apache.hc.core5.http.io.entity.StringEntity: void <init>(java.lang.String)>":
                case "<org.apache.hc.core5.http.io.entity.StringEntity: void <init>(java.lang.String,org.apache.hc.core5.http.ContentType)>":
                case "<org.apache.hc.core5.http.io.entity.StringEntity: void <init>(java.lang.String,org.apache.hc.core5.http.ContentType,boolean)>":
                case "<org.apache.hc.core5.http.io.entity.StringEntity: void <init>(java.lang.String,org.apache.hc.core5.http.ContentType,java.lang.String,boolean)>": {
                    return SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                }
            }
        }
        return new HashSet<>();
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }


    @Override
    public HashSet<?> handleAssignConstant(AssignStmt stmt, Value rightValue, Value
            leftOp, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignNewArrayExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>>
            currentValues) {
        NewArrayExpr newArrayExpr = ((NewArrayExpr) rightValue);
        if (newArrayExpr.getBaseType().toString().equals("org.apache.hc.core5.http.HttpEntity")) {
            return SimulationUtil.initArray(null, newArrayExpr, currentValues);
        }
        return null;
    }


    @Override
    public HashSet<?> handleAssignNewExpression(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>>
            currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignArithmeticExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>>
            currentValues) {
        return null;
    }

}