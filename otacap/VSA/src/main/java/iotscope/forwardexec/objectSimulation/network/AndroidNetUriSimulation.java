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
import soot.jimple.internal.AbstractInstanceInvokeExpr;

import java.util.HashMap;
import java.util.HashSet;

public class AndroidNetUriSimulation implements SimulationObjects {


    private static final Logger LOGGER = LoggerFactory.getLogger(AndroidNetUriSimulation.class);


    public AndroidNetUriSimulation() {
    }



    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
            return null;
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (signature.contains("android.net.Uri")) {
            HashSet<String> results = new HashSet<>();
            if (signature.equals("<android.net.Uri: java.lang.String decode(java.lang.String)>") || signature.equals("<android.net.Uri: java.lang.String decode(java.lang.String,java.lang.String)>") || signature.equals("<android.net.Uri: android.net.Uri parse(java.lang.String)>")) {
                HashSet<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                results.addAll(arg0);
            } else if (signature.equals("<android.net.Uri: java.lang.String fromParts(java.lang.String,java.lang.String,java.lang.String)>")) {
                HashSet<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                HashSet<String> arg1 = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                HashSet<String> arg2 = SimulationUtil.getStringContent(expr.getArg(0), currentValues);

                for (String s1 : arg0) {
                    for (String s2 : arg1) {
                        for (String s3 : arg2) {
                            String tmp = "";
                            tmp += s1 == null ? "" : s1;
                            tmp += s2 == null ? "" : s2;
                            tmp += s3 == null ? "" : s3;
                            results.add(tmp);
                        }
                    }
                }

            } else if (signature.equals("<android.net.Uri: java.lang.String toString()>")) {
                AbstractInstanceInvokeExpr instanceInvokeExpr = (AbstractInstanceInvokeExpr) expr;
                HashSet<String> base = SimulationUtil.getStringContent(instanceInvokeExpr.getBase(), currentValues);
                results.addAll(base);
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
        NewArrayExpr newArrayExpr = ((NewArrayExpr) rightValue);
        if (newArrayExpr.getBaseType().toString().equals("android.net.Uri")) {
            return SimulationUtil.initArray(null, newArrayExpr, currentValues);
        }
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
