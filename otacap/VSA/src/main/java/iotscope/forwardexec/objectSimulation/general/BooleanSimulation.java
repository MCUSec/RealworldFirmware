package iotscope.forwardexec.objectSimulation.general;

import java.util.HashMap;
import java.util.HashSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.DoubleConstant;
import soot.jimple.IntConstant;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.Stmt;
import soot.jimple.StringConstant;
import soot.jimple.VirtualInvokeExpr;

public class BooleanSimulation implements SimulationObjects {

    private static final Logger LOGGER = LoggerFactory.getLogger(BooleanSimulation.class);

    public BooleanSimulation() {

    }

    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (signature.equals("<java.lang.StringBuilder: java.lang.StringBuilder append(boolean)>") ){
            return transferValuesAndAppend(stmt, ((VirtualInvokeExpr) expr).getBase(), SimulationUtil.getStringContentFromBoolean(expr.getArg(0), currentValues), currentValues);
        }
        return null;
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr,
            HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignNewExpression(AssignStmt stmt, Value rightValue,
            HashMap<Value, HashSet<?>> currentValues) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public HashSet<?> handleAssignConstant(AssignStmt stmt, Value rightValue, Value leftOp,
            HashMap<Value, HashSet<?>> currentValues) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public HashSet<?> handleAssignNewArrayExpr(AssignStmt stmt, Value rightValue,
            HashMap<Value, HashSet<?>> currentValues) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public HashSet<?> handleAssignArithmeticExpr(AssignStmt stmt, Value rightValue,
            HashMap<Value, HashSet<?>> currentValues) {
        // TODO Auto-generated method stub
        return null;
    }

    private HashSet<String> transferValuesAndAppend(Stmt stmt, Value from, HashSet<String> appends, HashMap<Value, HashSet<?>> currentValues) {
        HashSet<String> currentValuesFrom = SimulationUtil.getStringContent(from, currentValues);
        if (currentValues == null) {
            currentValuesFrom = new HashSet<>();
            currentValuesFrom.add("");
            LOGGER.warn(String.format("[%s] [SIMULATE][transferValuesAndAppend values unknown]: %s", this.hashCode(), from));
        }
        else if (currentValuesFrom.size() == 0) {
            currentValuesFrom = new HashSet<>();
            currentValuesFrom.add("");
        }

        if(appends == null) {
            LOGGER.warn(String.format("[%s] [SIMULATE][transferValuesAndAppend arg unknown]: %s", this.hashCode(), stmt));
            appends = new HashSet<>();
            appends.add("");
        }
        else if (appends.size() == 0) {
            LOGGER.warn(String.format("[%s] [SIMULATE][transferValuesAndAppend arg unknown]: %s", this.hashCode(), stmt));
            appends = new HashSet<>();
            appends.add("");
        } 

        HashSet<String> newValues = new HashSet<>();
        for (String append : appends) {
            for (String str : currentValuesFrom) {
                if (append == null || str == null || newValues.size() >= 7000) {
                    continue;
                }
                if (append.startsWith("&") && str.contains(append)) {
                    LOGGER.debug("Do not append {}, because {} already contains it", append, str);
                    continue;
                }
                if (str.length() < 7000 && append.length() < 7000) {
                    newValues.add(str + append);
                } else if (append.length() < 7000) {
                    newValues.add(append);
                } else {
                    int min = Math.min(str.length(), 7000);
                    newValues.add(str.substring(0, min));
                }
            }
        }

        return (HashSet<String>) newValues.clone();
    }

    
}
