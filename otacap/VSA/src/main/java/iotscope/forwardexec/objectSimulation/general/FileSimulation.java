package iotscope.forwardexec.objectSimulation.general;

import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.NewArrayExpr;

import java.io.File;
import java.net.URI;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;

public class FileSimulation implements SimulationObjects {

    private static final Logger LOGGER = LoggerFactory.getLogger(FileSimulation.class);


    public FileSimulation() {
    }


    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (!signature.startsWith("<java.io.File")) {
            return null;
        }
        HashSet<File> result = new HashSet<>();
        if (signature.equals("<java.io.File: void <init>(java.io.File,java.lang.String)>")) {
            Iterator<File> arg0 = SimulationUtil.getFile(expr.getArg(0), currentValues).iterator();
            Iterator<String> arg1 = SimulationUtil.getStringContent(expr.getArg(1), currentValues).iterator();
            while (arg0.hasNext() && arg1.hasNext()) {
                try {
                    result.add(new File(arg0.next(), arg1.next()));
                } catch (Exception e) {
                    LOGGER.debug("Could not create new File object");
                }
            }
        } else if (signature.equals("<java.io.File: void <init>(java.lang.String)>")) {
            for (String s : SimulationUtil.getStringContent(expr.getArg(0), currentValues)) {
                try {
                    result.add(new File(s));
                } catch (Exception e) {
                    LOGGER.debug("Could not create new File object");
                }
            }
        } else if (signature.equals("<java.io.File: void <init>(java.lang.String,java.lang.String)>")) {
            Iterator<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues).iterator();
            Iterator<String> arg1 = SimulationUtil.getStringContent(expr.getArg(1), currentValues).iterator();
            while (arg0.hasNext() && arg1.hasNext()) {
                try {
                    result.add(new File(arg0.next(), arg1.next()));
                } catch (Exception e) {
                    LOGGER.debug("Could not create new File object");
                }
            }

        } else if (signature.equals("<java.io.File: void <init>(java.net.URI)>")) {
            for (URI uri : SimulationUtil.getJavaNetURI(expr.getArg(0), currentValues)) {
                try {
                    result.add(new File(uri));
                } catch (Exception e) {
                    LOGGER.debug("Could not create new File object");
                }
            }
        }
        return result;
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        return null;
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
        NewArrayExpr newArrayExpr = ((NewArrayExpr) rightValue);
        if (newArrayExpr.getBaseType().toString().equals("java.io.File")) {
            return SimulationUtil.initArray(new File(""), newArrayExpr, currentValues);
        }
        return null;
    }


    @Override
    public HashSet<?> handleAssignArithmeticExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {

        return null;
    }


}
